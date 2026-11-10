<?php
/**
 * Admin system (admin_system.md): users, customers, deployments and governance for the operator console.
 *
 * Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: change_plan follows billing change_plan (retrieve, exactly one item,
 * update {items: [{id, price}], proration_behavior: 'create_prorations'}; ADMIN-12); the caller must be an
 * active user; invite and reset e-mails go through an injected sender and the reset token is stored only as a
 * SHA-256 hash (it was written into the audit log); create_deployment initialises a config row; publish checks
 * the SafetyFlags.can_publish gate (fail closed) and domain_verified; governance approve executes the action.
 * Touches: the database, e-mail through the injected sender, Stripe through the injected gateway (money).
 */
declare(strict_types=1);

/**
 * The Stripe calls change_plan needs (stripe.subscriptions.retrieve / update), so it runs against a fake in tests.
 * Why: ADMIN-12 as amended. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the network (Stripe) and money in a real implementation.
 */
interface AdminStripeGateway
{
    /** stripe.subscriptions.retrieve: returns an object with items->data[] each having an id. */
    public function retrieveSubscription(string $subscriptionId): object;
    /** stripe.subscriptions.update with $params unchanged. */
    public function updateSubscription(string $subscriptionId, array $params): object;
}

class AdminSystem
{
    /** Stripe price id per plan tier (same placeholders as billing_subscriptions). */
    public const PRICE_IDS = [
        'solo' => 'price_1UIxxxxxx',
        'team' => 'price_1UIyyyyyy',
        'enterprise' => 'price_1UIzzzzzz',
    ];
    private PDO $pdo;
    /** @var ?Closure(string $to, string $subject, string $body): void */
    private ?Closure $mailer;
    private ?AdminStripeGateway $stripe;
    /** @var Closure(int $deploymentId): bool SafetyFlags.can_publish; default false (fail closed). */
    private Closure $canPublish;
    private int $current_user_id = 0;
    private string $current_user_tier = '';
    private const ALLOWED_TIERS = ['owner', 'admin', 'user'];
    /**
     * The token a page must send back with every write; compared in constant time. It was the constant
     * 'valid_csrf_token', which every attacker knows. It must outlive one request: the page that shows the
     * form and the POST that submits it build separate AdminSystem objects. So it is the caller's session
     * token when one is passed, else the one kept in $_SESSION (made once per session), else, with no
     * session, a random one for this object only.
     */
    private string $csrfToken;
    private const SESSION_CSRF_KEY = 'admin_system_csrf_token';

    /**
     * Builds the admin service on a PDO connection and creates its schema.
     * The CSRF token is the given session token, else $_SESSION's, else a random one for this object only.
     * Touches: the database (schema). Reviewed in PR 18 (2026-11-09, session 04ec72ff).
     *
     * $deps (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP): 'mailer' => fn(to, subject, body) for invite and reset e-mails;
     * 'stripe' => AdminStripeGateway for change_plan; 'can_publish' => fn(int deployment_id): bool, the
     * SafetyFlags.can_publish half of publish's double gate (missing = false, so nothing publishes by accident).
     */
    public function __construct(PDO $pdo, ?string $csrfToken = null, array $deps = [])
    {
        $this->pdo = $pdo;
        $this->mailer = $deps['mailer'] ?? null;
        $this->stripe = $deps['stripe'] ?? null;
        $this->canPublish = $deps['can_publish'] ?? static fn(int $deploymentId): bool => false;
        if ($csrfToken !== null && $csrfToken !== '') {
            $this->csrfToken = $csrfToken;
        } elseif (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION[self::SESSION_CSRF_KEY] ??= bin2hex(random_bytes(32));
            $this->csrfToken = $_SESSION[self::SESSION_CSRF_KEY];
        } else {
            $this->csrfToken = bin2hex(random_bytes(32));
        }
        $this->initializeSchema();
    }

    /**
     * Set the caller. $user_id must be the id of the VERIFIED session user (from verify_access_token or the
     * framework's session), never a value from the request body, query or headers; the role is read from the
     * users table, never taken from the client. A suspended (or otherwise non-active) user cannot act.
     * Input: user id. Output: none; RuntimeException when the user is missing or not active.
     * Why: common rule "identity comes from the verified caller"; the status check is 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (read).
     */
    public function setCurrentUser(int $user_id): void
    {
        $stmt = $this->pdo->prepare('SELECT tier, status FROM users WHERE id = :id');
        $stmt->execute([':id' => $user_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            throw new RuntimeException("User not found");
        }
        if ($row['status'] !== 'active') {
            throw new RuntimeException('user_not_active');
        }
        $this->current_user_id = $user_id;
        $this->current_user_tier = $row['tier'];
    }

    /**
     * The id of the user set with setCurrentUser (0 before that). Reviewed in PR 18 (2026-11-09, session 04ec72ff).
     */
    public function getCurrentUserId(): int
    {
        return $this->current_user_id;
    }

    /** The token the page must send back with every write. */
    public function csrfToken(): string
    {
        return $this->csrfToken;
    }

    /**
     * Throws RuntimeException unless the token matches this service's token (constant-time compare). Reviewed in PR 18 (2026-11-09, session 04ec72ff).
     */
    private function verify_csrf(string $token): void
    {
        if ($token === '' || !hash_equals($this->csrfToken, $token)) {
            throw new RuntimeException('Invalid CSRF token');
        }
    }

    private function require_owner(): void
    {
        if ($this->current_user_tier !== 'owner') {
            throw new RuntimeException('owner_only');
        }
    }

    private function require_admin_or_owner(): void
    {
        if (!in_array($this->current_user_tier, ['owner', 'admin'], true)) {
            throw new RuntimeException('admin_or_owner');
        }
    }

    private function validate_email(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    private function validate_name(string $name): bool
    {
        return strlen(trim($name)) >= 1 && strlen(trim($name)) <= 255;
    }

    private function validate_tier(string $tier): bool
    {
        return in_array($tier, self::ALLOWED_TIERS, true);
    }

    private function getCurrentTimestamp(): string
    {
        return (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
    }

    private function auditLog(string $action, int $actor_id, ?string $resource_type = null, ?int $resource_id = null, $old_value = null, $new_value = null, ?string $reason = null): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO audit_logs (action, actor_id, resource_type, resource_id, old_value, new_value, reason, timestamp) VALUES (:action, :actor_id, :resource_type, :resource_id, :old_value, :new_value, :reason, :timestamp)');
        $stmt->execute([
            ':action' => $action,
            ':actor_id' => $actor_id,
            ':resource_type' => $resource_type,
            ':resource_id' => $resource_id,
            ':old_value' => $old_value !== null ? json_encode($old_value) : null,
            ':new_value' => $new_value !== null ? json_encode($new_value) : null,
            ':reason' => $reason,
            ':timestamp' => $this->getCurrentTimestamp(),
        ]);
    }

    /**
     * Creates the users, customers, deployments, governance and audit tables if missing. Touches: the database. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
     */
    private function initializeSchema(): void
    {
        $sql = <<<SQL
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    tier TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_hash TEXT,
    stripe_customer_id TEXT
);
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    tier TEXT NOT NULL,
    signup_date TEXT NOT NULL,
    invoice_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    subscription_status TEXT,
    payment_method TEXT,
    address TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    tier TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    theme_id INTEGER,
    published_at TEXT,
    suspend_reason TEXT,
    archived_at TEXT,
    domain_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(customer_id) REFERENCES customers(id)
);
CREATE TABLE IF NOT EXISTS deployment_configs (
    deployment_id INTEGER PRIMARY KEY,
    theme_id INTEGER NOT NULL,
    tier TEXT NOT NULL,
    settings TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(deployment_id) REFERENCES deployments(id)
);
CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'queued',
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS governance_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    target_resource_id INTEGER,
    reason TEXT,
    submitted_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by INTEGER,
    approved_at TEXT,
    rejection_reason TEXT
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    actor_id INTEGER NOT NULL,
    resource_type TEXT,
    resource_id INTEGER,
    old_value TEXT,
    new_value TEXT,
    reason TEXT,
    timestamp TEXT NOT NULL
);
SQL;
        $this->pdo->exec($sql);
    }

    /* USERS DOMAIN */

    /**
     * Owner only: create a user ({csrf_token, email, name, tier, notify}) and, with notify, e-mail an invite
     * through the injected sender. Output: {success, user_id, email, tier, created_at} or {error, message}
     * (invalid_email, invalid_name, invalid_tier, email_exists, owner_only, Invalid CSRF token).
     * Why: ADMIN-01..03; the invite was a placeholder until 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (users, audit_logs) and e-mail.
     */
    public function createUser(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $email = trim($data['email'] ?? '');
            $name = trim($data['name'] ?? '');
            $tier = trim($data['tier'] ?? '');
            $notify = $data['notify'] ?? false;

            if (!$this->validate_email($email)) {
                return ['error' => 'invalid_email', 'message' => 'Invalid email format'];
            }
            if (!$this->validate_name($name)) {
                return ['error' => 'invalid_name', 'message' => 'Name must be 1-255 characters'];
            }
            if (!$this->validate_tier($tier)) {
                return ['error' => 'invalid_tier', 'message' => 'Invalid tier'];
            }

            $stmt = $this->pdo->prepare('SELECT id FROM users WHERE email = :email');
            $stmt->execute([':email' => $email]);
            if ($stmt->fetch(PDO::FETCH_ASSOC)) {
                return ['error' => 'email_exists', 'message' => 'Email already exists'];
            }

            $now = $this->getCurrentTimestamp();
            $stmt = $this->pdo->prepare('INSERT INTO users (email, name, tier, status, created_at, updated_at) VALUES (:email, :name, :tier, :status, :created_at, :updated_at)');
            $stmt->execute([
                ':email' => $email,
                ':name' => $name,
                ':tier' => $tier,
                ':status' => 'active',
                ':created_at' => $now,
                ':updated_at' => $now,
            ]);
            $user_id = (int)$this->pdo->lastInsertId();

            // Send the invite through the injected sender (ADMIN-01; it was a placeholder; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            if ($notify) {
                $this->sendMail($email, 'You have been invited', "Hello $name, an account was created for you. Sign in to set your password.");
            }

            $this->auditLog('user_created', $this->current_user_id, 'users', $user_id, null, ['email' => $email, 'tier' => $tier]);

            return ['success' => true, 'user_id' => $user_id, 'email' => $email, 'tier' => $tier, 'created_at' => $now];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Owner only: start a password reset for another user ({csrf_token, user_id}): a 32-byte token stored only
     * as SHA-256 with a 1 h expiry and e-mailed to the user; never the caller's own account or the last owner.
     * Output: {success, status: 'reset_email_sent'} or {error, message}.
     * Why: ADMIN-04/05; the token was written into the audit log in plain text and never sent (fixed
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP). Touches: the database (password_resets, audit_logs) and e-mail.
     */
    public function resetPassword(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $user_id = (int)($data['user_id'] ?? 0);
            if ($user_id === $this->current_user_id) {
                return ['error' => 'cannot_reset_own_password', 'message' => 'Cannot reset own password'];
            }

            $stmt = $this->pdo->prepare('SELECT id, email, tier, status FROM users WHERE id = :id');
            $stmt->execute([':id' => $user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                return ['error' => 'user_not_found', 'message' => 'User not found'];
            }

            if ($user['tier'] === 'owner' && $this->countOwners() <= 1) {
                return ['error' => 'cannot_demote_last_owner', 'message' => 'Cannot demote last active owner'];
            }

            // Reset token: 32 random bytes, stored only as SHA-256 with a 1 h expiry, e-mailed to the user, never
            // logged (it was written into the audit log in plain text; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            $reset_token = bin2hex(random_bytes(32));
            $now = $this->getCurrentTimestamp();
            $this->pdo->prepare('INSERT INTO password_resets (user_id, token_hash, expires_at, created_by, created_at) VALUES (:user_id, :hash, :expires_at, :created_by, :created_at)')
                ->execute([
                    ':user_id' => $user_id,
                    ':hash' => hash('sha256', $reset_token),
                    ':expires_at' => (new DateTime('now +1 hour', new DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
                    ':created_by' => $this->current_user_id,
                    ':created_at' => $now,
                ]);
            $this->sendMail((string)$user['email'], 'Reset your password', "Use this link to choose a new password: /reset-password?token=$reset_token");
            $this->auditLog('password_reset_initiated', $this->current_user_id, 'users', $user_id);

            return ['success' => true, 'status' => 'reset_email_sent'];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Changes a user's tier after the CSRF check; refuses an invalid tier, demoting the last active owner and the
     * caller's own role. Output: success or an error array. Touches: users and audit_logs. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
     */
    public function changeRole(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $user_id = (int)($data['user_id'] ?? 0);
            $new_tier = trim($data['new_tier'] ?? '');

            if (!$this->validate_tier($new_tier)) {
                return ['error' => 'invalid_tier', 'message' => 'Invalid tier'];
            }

            $stmt = $this->pdo->prepare('SELECT tier FROM users WHERE id = :id');
            $stmt->execute([':id' => $user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                return ['error' => 'user_not_found', 'message' => 'User not found'];
            }

            // Check if trying to demote the last active owner (takes precedence over own-role check)
            if ($user['tier'] === 'owner' && $this->countOwners() <= 1 && $new_tier !== 'owner') {
                return ['error' => 'cannot_demote_last_owner', 'message' => 'Cannot demote last active owner'];
            }

            if ($user_id === $this->current_user_id) {
                return ['error' => 'cannot_change_own_role', 'message' => 'Cannot change own role'];
            }

            $old_tier = $user['tier'];
            $stmt = $this->pdo->prepare('UPDATE users SET tier = :tier, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':tier' => $new_tier,
                ':updated_at' => $this->getCurrentTimestamp(),
                ':id' => $user_id,
            ]);

            $this->auditLog('role_changed', $this->current_user_id, 'users', $user_id, ['tier' => $old_tier], ['tier' => $new_tier]);

            return ['success' => true, 'user_id' => $user_id, 'old_tier' => $old_tier, 'new_tier' => $new_tier];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function suspendUser(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $user_id = (int)($data['user_id'] ?? 0);
            $reason = trim($data['reason'] ?? '');

            if ($user_id === $this->current_user_id) {
                return ['error' => 'cannot_suspend_yourself', 'message' => 'Cannot suspend yourself'];
            }

            $stmt = $this->pdo->prepare('SELECT tier FROM users WHERE id = :id');
            $stmt->execute([':id' => $user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                return ['error' => 'user_not_found', 'message' => 'User not found'];
            }

            if ($user['tier'] === 'owner' && $this->countOwners() <= 1) {
                return ['error' => 'cannot_demote_last_owner', 'message' => 'Cannot demote last active owner'];
            }

            $stmt = $this->pdo->prepare('UPDATE users SET status = :status, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':status' => 'suspended',
                ':updated_at' => $this->getCurrentTimestamp(),
                ':id' => $user_id,
            ]);

            $this->auditLog('user_suspended', $this->current_user_id, 'users', $user_id, null, ['status' => 'suspended'], $reason);

            return ['success' => true, 'user_id' => $user_id, 'suspended' => true];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Send an e-mail through the injected sender; without one nothing is sent.
     * Inputs: address, subject, body. Output: none. Why: ADMIN-01/04 ("invite sent", "email sent") were
     * placeholders. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the e-mail service behind the sender.
     */
    private function sendMail(string $to, string $subject, string $body): void
    {
        if ($this->mailer !== null) {
            ($this->mailer)($to, $subject, $body);
        }
    }

    private function countOwners(): int
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) as cnt FROM users WHERE tier = :tier AND status = :status');
        $stmt->execute([':tier' => 'owner', ':status' => 'active']);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return (int)($row['cnt'] ?? 0);
    }

    /* CUSTOMERS DOMAIN */

    /**
     * Admin or owner: one page of customers, newest signup first, ties in insertion order.
     * Output: [{customer_id, email, name, tier, signup_date, invoice_count, status}] or {error, message}.
     * Why: ADMIN-10; the tie-break is 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (equal signup dates could repeat or skip
     * a customer across pages). Touches: the database (read).
     */
    public function listCustomers(int $page = 1, int $per_page = 20): array
    {
        try {
            $this->require_admin_or_owner();

            $offset = ($page - 1) * $per_page;
            // Ties on signup_date keep insertion order (id), so pages never overlap (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            $stmt = $this->pdo->prepare('SELECT id as customer_id, email, name, tier, signup_date, invoice_count, status FROM customers ORDER BY signup_date DESC, id ASC LIMIT :limit OFFSET :offset');
            $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $customers = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $customers;
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function getCustomer(int $customer_id): array
    {
        try {
            $this->require_admin_or_owner();

            $stmt = $this->pdo->prepare('SELECT id as customer_id, email, name, tier, subscription_status, payment_method, address, notes FROM customers WHERE id = :id');
            $stmt->execute([':id' => $customer_id]);
            $customer = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$customer) {
                return ['error' => 'customer_not_found', 'message' => 'Customer not found'];
            }
            return $customer;
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Owner only: move a customer's subscription to another plan tier, by the billing change_plan rule.
     *
     * Input: {csrf_token, customer_id, new_tier (solo | team | enterprise)}. Output: {success, customer_id,
     * old_tier, new_tier, effective_date} or {error, message}: invalid_tier (400), customer_not_found,
     * no_subscription, stripe_not_configured, subscription_item_ambiguous (409, not exactly one item),
     * stripe_error. The tier check and the item check both come before any update; the update is
     * {items: [{id: current_item_id, price}], proration_behavior: 'create_prorations'} (never a bare price,
     * which adds a second item and bills both plans). Then customers.tier and audit_log plan_changed.
     * Why: ADMIN-12 as amended; it validated new_tier against user roles and never called Stripe.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: Stripe (what the customer pays), the database, the audit log.
     */
    public function changePlan(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $customer_id = (int)($data['customer_id'] ?? 0);
            $new_tier = trim((string)($data['new_tier'] ?? ''));

            if (!isset(self::PRICE_IDS[$new_tier])) {
                return ['error' => 'invalid_tier', 'status' => 400, 'message' => 'Invalid tier'];
            }

            $stmt = $this->pdo->prepare('SELECT stripe_subscription_id, tier FROM customers WHERE id = :id');
            $stmt->execute([':id' => $customer_id]);
            $customer = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$customer) {
                return ['error' => 'customer_not_found', 'message' => 'Customer not found'];
            }
            $subscription_id = (string)($customer['stripe_subscription_id'] ?? '');
            if ($subscription_id === '') {
                return ['error' => 'no_subscription', 'message' => 'Customer has no subscription'];
            }
            if ($this->stripe === null) {
                return ['error' => 'stripe_not_configured', 'message' => 'Stripe is not configured'];
            }

            try {
                $remote = $this->stripe->retrieveSubscription($subscription_id);
            } catch (Throwable) {
                return ['error' => 'stripe_error', 'message' => 'The payment provider rejected the request'];
            }
            $itemIds = [];
            foreach (($remote->items->data ?? []) as $item) {
                $itemIds[] = is_array($item) ? ($item['id'] ?? null) : ($item->id ?? null);
            }
            if (count($itemIds) !== 1 || !is_string($itemIds[0]) || $itemIds[0] === '') {
                return ['error' => 'subscription_item_ambiguous', 'status' => 409, 'message' => 'The subscription does not have exactly one item'];
            }
            try {
                $updated = $this->stripe->updateSubscription($subscription_id, [
                    'items' => [['id' => $itemIds[0], 'price' => self::PRICE_IDS[$new_tier]]],
                    'proration_behavior' => 'create_prorations',
                ]);
            } catch (Throwable) {
                return ['error' => 'stripe_error', 'message' => 'The payment provider rejected the request'];
            }

            $old_tier = $customer['tier'];
            $this->pdo->beginTransaction();
            $stmt = $this->pdo->prepare('UPDATE customers SET tier = :tier, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':tier' => $new_tier,
                ':updated_at' => $this->getCurrentTimestamp(),
                ':id' => $customer_id,
            ]);
            $this->auditLog('plan_changed', $this->current_user_id, 'customers', $customer_id, ['tier' => $old_tier], ['tier' => $new_tier]);
            $this->pdo->commit();

            $effective = isset($updated->current_period_end) && is_int($updated->current_period_end)
                ? gmdate('Y-m-d H:i:s', $updated->current_period_end) : $this->getCurrentTimestamp();
            return ['success' => true, 'customer_id' => $customer_id, 'old_tier' => $old_tier, 'new_tier' => $new_tier, 'effective_date' => $effective];
        } catch (RuntimeException $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function queueRefund(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $invoice_id = (int)($data['invoice_id'] ?? 0);
            $amount = (float)($data['amount'] ?? 0);
            $reason = trim($data['reason'] ?? '');

            // Simulate invoice check
            // In real implementation, query invoices table
            if ($invoice_id <= 0) {
                return ['error' => 'invoice_not_found', 'message' => 'Invoice not found'];
            }

            $now = $this->getCurrentTimestamp();
            $stmt = $this->pdo->prepare('INSERT INTO refunds (invoice_id, amount, reason, status, created_by, created_at) VALUES (:invoice_id, :amount, :reason, :status, :created_by, :created_at)');
            $stmt->execute([
                ':invoice_id' => $invoice_id,
                ':amount' => $amount,
                ':reason' => $reason,
                ':status' => 'queued',
                ':created_by' => $this->current_user_id,
                ':created_at' => $now,
            ]);
            $refund_id = (int)$this->pdo->lastInsertId();

            $this->auditLog('refund_queued', $this->current_user_id, 'refunds', $refund_id, null, ['invoice_id' => $invoice_id, 'amount' => $amount, 'reason' => $reason]);

            return ['success' => true, 'refund_id' => $refund_id, 'status' => 'queued', 'amount' => $amount];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /* DEPLOYMENTS DOMAIN */

    public function listDeployments(): array
    {
        try {
            $this->require_admin_or_owner();

            $stmt = $this->pdo->prepare('SELECT id as deployment_id, customer_id, domain, tier, status, theme_id, published_at FROM deployments ORDER BY published_at DESC');
            $stmt->execute();
            $deployments = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $deployments;
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Owner only: create a draft deployment ({csrf_token, customer_id, domain, tier, theme_id}) and initialise
     * its config row. Output: {success, deployment_id, domain, tier} or {error, message}.
     * Why: ADMIN-14; the config row replaced a placeholder 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (deployments, deployment_configs, audit_logs).
     */
    public function createDeployment(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $customer_id = (int)($data['customer_id'] ?? 0);
            $domain = trim($data['domain'] ?? '');
            $tier = trim($data['tier'] ?? '');
            $theme_id = (int)($data['theme_id'] ?? 0);

            if (!$this->validate_tier($tier)) {
                return ['error' => 'invalid_tier', 'message' => 'Invalid tier'];
            }

            // Check customer exists
            $stmt = $this->pdo->prepare('SELECT id FROM customers WHERE id = :id');
            $stmt->execute([':id' => $customer_id]);
            if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
                return ['error' => 'customer_not_found', 'message' => 'Customer not found'];
            }

            // Check domain not registered
            $stmt = $this->pdo->prepare('SELECT id FROM deployments WHERE domain = :domain');
            $stmt->execute([':domain' => $domain]);
            if ($stmt->fetch(PDO::FETCH_ASSOC)) {
                return ['error' => 'domain_already_registered', 'message' => 'Domain already registered'];
            }

            // Check theme exists (simulate)
            if ($theme_id <= 0) {
                return ['error' => 'theme_not_found', 'message' => 'Theme not found'];
            }

            $now = $this->getCurrentTimestamp();
            $stmt = $this->pdo->prepare('INSERT INTO deployments (customer_id, domain, tier, status, theme_id, created_at, updated_at) VALUES (:customer_id, :domain, :tier, :status, :theme_id, :created_at, :updated_at)');
            $stmt->execute([
                ':customer_id' => $customer_id,
                ':domain' => $domain,
                ':tier' => $tier,
                ':status' => 'draft',
                ':theme_id' => $theme_id,
                ':created_at' => $now,
                ':updated_at' => $now,
            ]);
            $deployment_id = (int)$this->pdo->lastInsertId();

            // Initialise the deployment's config (ADMIN-14; it was a placeholder; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            $this->pdo->prepare('INSERT INTO deployment_configs (deployment_id, theme_id, tier, settings, created_at) VALUES (:id, :theme_id, :tier, :settings, :created_at)')
                ->execute([
                    ':id' => $deployment_id,
                    ':theme_id' => $theme_id,
                    ':tier' => $tier,
                    ':settings' => json_encode(['domain' => $domain, 'theme_id' => $theme_id, 'tier' => $tier]),
                    ':created_at' => $now,
                ]);

            $this->auditLog('deployment_created', $this->current_user_id, 'deployments', $deployment_id, null, ['customer_id' => $customer_id, 'domain' => $domain, 'tier' => $tier]);

            return ['success' => true, 'deployment_id' => $deployment_id, 'domain' => $domain, 'tier' => $tier];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Double gate: owner only AND SafetyFlags.can_publish (injected; off by default); then the deployment must
     * be a draft with a verified domain and a theme. Output: {success, deployment_id, status: 'live',
     * public_url} or {error, message} (owner_only, publish_not_allowed, domain_not_verified, theme_not_set, ...).
     * Why: ADMIN-15; the flag and the domain check were placeholders until 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (deployments, audit_logs).
     */
    public function publishDeployment(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            // Double gate (ADMIN-15): require_owner() above AND SafetyFlags.can_publish here; the flag was never
            // checked, and domain_verified was "simulated" (2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
            $deployment_id = (int)($data['deployment_id'] ?? 0);
            $stmt = $this->pdo->prepare('SELECT status, theme_id, domain, domain_verified FROM deployments WHERE id = :id');
            $stmt->execute([':id' => $deployment_id]);
            $deployment = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$deployment) {
                return ['error' => 'deployment_not_found', 'message' => 'Deployment not found'];
            }

            if ($deployment['status'] !== 'draft') {
                return ['error' => 'deployment_not_in_draft', 'message' => 'Deployment not in draft status'];
            }

            if (!(bool)($this->canPublish)($deployment_id)) {
                return ['error' => 'publish_not_allowed', 'message' => 'SafetyFlags.can_publish is off'];
            }

            if ((int)$deployment['domain_verified'] !== 1) {
                return ['error' => 'domain_not_verified', 'message' => 'Domain not verified'];
            }

            if (empty($deployment['theme_id'])) {
                return ['error' => 'theme_not_set', 'message' => 'Theme not set'];
            }

            $now = $this->getCurrentTimestamp();
            $stmt = $this->pdo->prepare('UPDATE deployments SET status = :status, published_at = :published_at, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':status' => 'live',
                ':published_at' => $now,
                ':updated_at' => $now,
                ':id' => $deployment_id,
            ]);

            $public_url = 'https://' . $deployment['domain'];

            $this->auditLog('deployment_published', $this->current_user_id, 'deployments', $deployment_id, ['status' => 'draft'], ['status' => 'live']);

            return ['success' => true, 'deployment_id' => $deployment_id, 'status' => 'live', 'public_url' => $public_url];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function suspendDeployment(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $deployment_id = (int)($data['deployment_id'] ?? 0);
            $reason = trim($data['reason'] ?? '');

            $stmt = $this->pdo->prepare('SELECT status FROM deployments WHERE id = :id');
            $stmt->execute([':id' => $deployment_id]);
            $deployment = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$deployment) {
                return ['error' => 'deployment_not_found', 'message' => 'Deployment not found'];
            }

            $stmt = $this->pdo->prepare('UPDATE deployments SET status = :status, suspend_reason = :reason, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':status' => 'suspended',
                ':reason' => $reason,
                ':updated_at' => $this->getCurrentTimestamp(),
                ':id' => $deployment_id,
            ]);

            $this->auditLog('deployment_suspended', $this->current_user_id, 'deployments', $deployment_id, ['status' => $deployment['status']], ['status' => 'suspended'], $reason);

            return ['success' => true, 'deployment_id' => $deployment_id, 'status' => 'suspended'];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function retireDeployment(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $deployment_id = (int)($data['deployment_id'] ?? 0);

            $stmt = $this->pdo->prepare('SELECT status FROM deployments WHERE id = :id');
            $stmt->execute([':id' => $deployment_id]);
            $deployment = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$deployment) {
                return ['error' => 'deployment_not_found', 'message' => 'Deployment not found'];
            }

            $now = $this->getCurrentTimestamp();
            $stmt = $this->pdo->prepare('UPDATE deployments SET status = :status, archived_at = :archived_at, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':status' => 'archived',
                ':archived_at' => $now,
                ':updated_at' => $now,
                ':id' => $deployment_id,
            ]);

            $this->auditLog('deployment_archived', $this->current_user_id, 'deployments', $deployment_id, ['status' => $deployment['status']], ['status' => 'archived']);

            return ['success' => true, 'deployment_id' => $deployment_id, 'status' => 'archived'];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /* GOVERNANCE DOMAIN */

    public function listGovernanceActions(int $page = 1, int $per_page = 20): array
    {
        try {
            $this->require_admin_or_owner();

            $offset = ($page - 1) * $per_page;
            $stmt = $this->pdo->prepare('SELECT id as action_id, action_type, actor_id, target_resource_id, reason, submitted_at, status FROM governance_actions ORDER BY submitted_at DESC LIMIT :limit OFFSET :offset');
            $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $actions = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $actions;
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Owner only: approve (execute the action, then mark it approved) or reject (with a reason) a pending
     * governance action. Output: {success, action_id, status} or {error, message}; an action that cannot be
     * executed stays pending. Why: ADMIN-16/17; approval only "simulated" the action until
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the database (governance_actions, the target rows, audit_logs).
     */
    public function decideGovernanceAction(int $action_id, string $decide, array $data = []): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $stmt = $this->pdo->prepare('SELECT * FROM governance_actions WHERE id = :id');
            $stmt->execute([':id' => $action_id]);
            $action = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$action) {
                return ['error' => 'action_not_found', 'message' => 'Action not found'];
            }

            if ($action['status'] !== 'pending') {
                return ['error' => 'action_already_decided', 'message' => 'Action already decided'];
            }

            if ($decide === 'approve') {
                // Execute the original action first; an action that cannot run stays pending (ADMIN-16; it was
                // only simulated; 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP).
                $execution = $this->executeGovernanceAction($action);
                if (isset($execution['error'])) {
                    return $execution;
                }
                $stmt = $this->pdo->prepare('UPDATE governance_actions SET status = :status, approved_by = :approved_by, approved_at = :approved_at WHERE id = :id');
                $stmt->execute([
                    ':status' => 'approved',
                    ':approved_by' => $this->current_user_id,
                    ':approved_at' => $this->getCurrentTimestamp(),
                    ':id' => $action_id,
                ]);

                $this->auditLog('action_approved', $this->current_user_id, 'governance_actions', $action_id, null, ['status' => 'approved', 'execution_result' => $execution]);

                return ['success' => true, 'action_id' => $action_id, 'status' => 'approved'];
            } elseif ($decide === 'reject') {
                $reason = trim($data['reason'] ?? '');
                if ($reason === '') {
                    return ['error' => 'reason_required', 'message' => 'Reason required for rejection'];
                }
                $stmt = $this->pdo->prepare('UPDATE governance_actions SET status = :status, rejection_reason = :reason, approved_at = :approved_at WHERE id = :id');
                $stmt->execute([
                    ':status' => 'rejected',
                    ':reason' => $reason,
                    ':approved_at' => $this->getCurrentTimestamp(),
                    ':id' => $action_id,
                ]);

                $this->auditLog('action_rejected', $this->current_user_id, 'governance_actions', $action_id, null, ['status' => 'rejected'], $reason);

                return ['success' => true, 'action_id' => $action_id, 'status' => 'rejected'];
            } else {
                return ['error' => 'invalid_decide', 'message' => 'Invalid decide value'];
            }
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    /**
     * Run an approved governance action. Supported action types: suspend_user and delete_user (target a user;
     * never the approver, never the last active owner), suspend_deployment and retire_deployment (target a
     * deployment). Input: the governance_actions row. Output: {executed: action_type, target} or
     * {error, message} (unsupported_action_type, user_not_found, deployment_not_found, cannot_suspend_yourself,
     * cannot_demote_last_owner). Why: ADMIN-16 "action executed". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: the database (users or deployments) and the audit log.
     */
    private function executeGovernanceAction(array $action): array
    {
        $target = (int)$action['target_resource_id'];
        $type = (string)$action['action_type'];
        if ($type === 'suspend_user' || $type === 'delete_user') {
            if ($target === $this->current_user_id) {
                return ['error' => 'cannot_suspend_yourself', 'message' => 'Cannot act on yourself'];
            }
            $stmt = $this->pdo->prepare('SELECT tier, status FROM users WHERE id = :id');
            $stmt->execute([':id' => $target]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                return ['error' => 'user_not_found', 'message' => 'User not found'];
            }
            if ($user['tier'] === 'owner' && $this->countOwners() <= 1) {
                return ['error' => 'cannot_demote_last_owner', 'message' => 'Cannot remove the last active owner'];
            }
            $newStatus = $type === 'suspend_user' ? 'suspended' : 'deleted';
            $this->pdo->prepare('UPDATE users SET status = :status, updated_at = :now WHERE id = :id')
                ->execute([':status' => $newStatus, ':now' => $this->getCurrentTimestamp(), ':id' => $target]);
            $this->auditLog($type === 'suspend_user' ? 'user_suspended' : 'user_deleted', $this->current_user_id, 'users', $target, ['status' => $user['status']], ['status' => $newStatus], (string)$action['reason']);
            return ['executed' => $type, 'target' => $target];
        }
        if ($type === 'suspend_deployment' || $type === 'retire_deployment') {
            $stmt = $this->pdo->prepare('SELECT status FROM deployments WHERE id = :id');
            $stmt->execute([':id' => $target]);
            $deployment = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$deployment) {
                return ['error' => 'deployment_not_found', 'message' => 'Deployment not found'];
            }
            $newStatus = $type === 'suspend_deployment' ? 'suspended' : 'archived';
            $this->pdo->prepare('UPDATE deployments SET status = :status, updated_at = :now WHERE id = :id')
                ->execute([':status' => $newStatus, ':now' => $this->getCurrentTimestamp(), ':id' => $target]);
            $this->auditLog($type === 'suspend_deployment' ? 'deployment_suspended' : 'deployment_archived', $this->current_user_id, 'deployments', $target, ['status' => $deployment['status']], ['status' => $newStatus], (string)$action['reason']);
            return ['executed' => $type, 'target' => $target];
        }
        return ['error' => 'unsupported_action_type', 'message' => 'Unsupported action type'];
    }

    /* AUDIT LOG SEARCH */

    /**
     * Admin or owner: filters the audit log by the given fields. Output: matching rows. Touches: reads audit_logs. Reviewed in PR 18 (2026-11-09, session 04ec72ff).
     * Newest first; equal timestamps newest insertion first, so limit/offset pages never overlap (tie-break
     * added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP, ADMIN-18).
     */
    public function searchAuditLog(array $filters): array
    {
        try {
            $this->require_admin_or_owner();

            $action_type = $filters['action_type'] ?? null;
            $resource_id = $filters['resource_id'] ?? null;
            $date_from = $filters['date_from'] ?? null;
            $date_to = $filters['date_to'] ?? null;
            $limit = (int)($filters['limit'] ?? 100);
            $offset = (int)($filters['offset'] ?? 0);

            $sql = 'SELECT timestamp, actor_id, action, resource_type, resource_id, old_value, new_value, reason FROM audit_logs WHERE 1=1';
            $params = [];

            if ($action_type) {
                $sql .= ' AND action = :action_type';
                $params[':action_type'] = $action_type;
            }
            if ($resource_id) {
                $sql .= ' AND resource_id = :resource_id';
                $params[':resource_id'] = $resource_id;
            }
            if ($date_from) {
                $sql .= ' AND timestamp >= :date_from';
                $params[':date_from'] = $date_from;
            }
            if ($date_to) {
                $sql .= ' AND timestamp <= :date_to';
                $params[':date_to'] = $date_to;
            }

            $sql .= ' ORDER BY timestamp DESC, id DESC LIMIT :limit OFFSET :offset';
            $stmt = $this->pdo->prepare($sql);
            foreach ($params as $k => $v) {
                $stmt->bindValue($k, $v);
            }
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $logs;
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }
}
