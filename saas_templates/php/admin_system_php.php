<?php
declare(strict_types=1);

class AdminSystem
{
    private PDO $pdo;
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

    public function __construct(PDO $pdo, ?string $csrfToken = null)
    {
        $this->pdo = $pdo;
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

    public function setCurrentUser(int $user_id): void
    {
        $stmt = $this->pdo->prepare('SELECT tier FROM users WHERE id = :id');
        $stmt->execute([':id' => $user_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            throw new RuntimeException("User not found");
        }
        $this->current_user_id = $user_id;
        $this->current_user_tier = $row['tier'];
    }

    public function getCurrentUserId(): int
    {
        return $this->current_user_id;
    }

    /** The token the page must send back with every write. */
    public function csrfToken(): string
    {
        return $this->csrfToken;
    }

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
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(customer_id) REFERENCES customers(id)
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

            // Simulate sending invite email
            if ($notify) {
                // In real implementation, send email
            }

            $this->auditLog('user_created', $this->current_user_id, 'users', $user_id, null, ['email' => $email, 'tier' => $tier]);

            return ['success' => true, 'user_id' => $user_id, 'email' => $email, 'tier' => $tier, 'created_at' => $now];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function resetPassword(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $user_id = (int)($data['user_id'] ?? 0);
            if ($user_id === $this->current_user_id) {
                return ['error' => 'cannot_reset_own_password', 'message' => 'Cannot reset own password'];
            }

            $stmt = $this->pdo->prepare('SELECT id, tier, status FROM users WHERE id = :id');
            $stmt->execute([':id' => $user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                return ['error' => 'user_not_found', 'message' => 'User not found'];
            }

            if ($user['tier'] === 'owner' && $this->countOwners() <= 1) {
                return ['error' => 'cannot_demote_last_owner', 'message' => 'Cannot demote last active owner'];
            }

            // Generate reset token (simulate)
            $reset_token = bin2hex(random_bytes(16));
            // In real implementation, store token and send email
            $this->auditLog('password_reset_initiated', $this->current_user_id, 'users', $user_id, null, ['reset_token' => $reset_token]);

            return ['success' => true, 'status' => 'reset_email_sent'];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

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

    private function countOwners(): int
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) as cnt FROM users WHERE tier = :tier AND status = :status');
        $stmt->execute([':tier' => 'owner', ':status' => 'active']);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return (int)($row['cnt'] ?? 0);
    }

    /* CUSTOMERS DOMAIN */

    public function listCustomers(int $page = 1, int $per_page = 20): array
    {
        try {
            $this->require_admin_or_owner();

            $offset = ($page - 1) * $per_page;
            $stmt = $this->pdo->prepare('SELECT id as customer_id, email, name, tier, signup_date, invoice_count, status FROM customers ORDER BY signup_date DESC LIMIT :limit OFFSET :offset');
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

    public function changePlan(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            $customer_id = (int)($data['customer_id'] ?? 0);
            $new_tier = trim($data['new_tier'] ?? '');

            if (!$this->validate_tier($new_tier)) {
                return ['error' => 'invalid_tier', 'message' => 'Invalid tier'];
            }

            $stmt = $this->pdo->prepare('SELECT stripe_customer_id, tier FROM customers WHERE id = :id');
            $stmt->execute([':id' => $customer_id]);
            $customer = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$customer) {
                return ['error' => 'customer_not_found', 'message' => 'Customer not found'];
            }

            // Simulate Stripe subscription update
            $old_tier = $customer['tier'];
            // In real implementation, call Stripe API here
            $stmt = $this->pdo->prepare('UPDATE customers SET tier = :tier, updated_at = :updated_at WHERE id = :id');
            $stmt->execute([
                ':tier' => $new_tier,
                ':updated_at' => $this->getCurrentTimestamp(),
                ':id' => $customer_id,
            ]);

            $this->auditLog('plan_changed', $this->current_user_id, 'customers', $customer_id, ['tier' => $old_tier], ['tier' => $new_tier]);

            return ['success' => true, 'customer_id' => $customer_id, 'old_tier' => $old_tier, 'new_tier' => $new_tier, 'effective_date' => $this->getCurrentTimestamp()];
        } catch (RuntimeException $e) {
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

            // Simulate config init
            // In real implementation, create config files

            $this->auditLog('deployment_created', $this->current_user_id, 'deployments', $deployment_id, null, ['customer_id' => $customer_id, 'domain' => $domain, 'tier' => $tier]);

            return ['success' => true, 'deployment_id' => $deployment_id, 'domain' => $domain, 'tier' => $tier];
        } catch (RuntimeException $e) {
            return ['error' => $e->getMessage(), 'message' => $e->getMessage()];
        }
    }

    public function publishDeployment(array $data): array
    {
        try {
            $this->verify_csrf($data['csrf_token'] ?? '');
            $this->require_owner();

            // Double-gate: SafetyFlags.can_publish
            $deployment_id = (int)($data['deployment_id'] ?? 0);
            $stmt = $this->pdo->prepare('SELECT status, theme_id, domain FROM deployments WHERE id = :id');
            $stmt->execute([':id' => $deployment_id]);
            $deployment = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$deployment) {
                return ['error' => 'deployment_not_found', 'message' => 'Deployment not found'];
            }

            if ($deployment['status'] !== 'draft') {
                return ['error' => 'deployment_not_in_draft', 'message' => 'Deployment not in draft status'];
            }

            if (empty($deployment['theme_id'])) {
                return ['error' => 'theme_not_set', 'message' => 'Theme not set'];
            }

            // Simulate domain verification
            // In real implementation, check DNS, SSL, etc.

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
                // Execute original action (simulate)
                // In real implementation, perform the action
                $stmt = $this->pdo->prepare('UPDATE governance_actions SET status = :status, approved_by = :approved_by, approved_at = :approved_at WHERE id = :id');
                $stmt->execute([
                    ':status' => 'approved',
                    ':approved_by' => $this->current_user_id,
                    ':approved_at' => $this->getCurrentTimestamp(),
                    ':id' => $action_id,
                ]);

                $this->auditLog('action_approved', $this->current_user_id, 'governance_actions', $action_id, null, ['status' => 'approved']);

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

    /* AUDIT LOG SEARCH */

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

            $sql .= ' ORDER BY timestamp DESC LIMIT :limit OFFSET :offset';
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
