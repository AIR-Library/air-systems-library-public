package rbac

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ---------- Tier definitions ----------
type Tier string

const (
	TierOwner    Tier = "owner"
	TierAdmin    Tier = "admin"
	TierMember   Tier = "member"
	TierPublic   Tier = "public"
	TierService  Tier = "service"
)

// ---------- User ----------
type User struct {
	ID   string
	Tier Tier
}

// ---------- RBAC Error ----------
type RBACError struct {
	Code    int
	Message string
}

func (e *RBACError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

// ---------- Audit ----------
// AuditEntry is one audit_log row. TargetID and DeletedItems (added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP) carry the org id and the counts the org cascade logs
// (spec RBAC-06: deleted_items={deployments, api_keys, invitations, memberships}).
type AuditEntry struct {
	Action       string
	UserID       string
	Endpoint     string
	RequiredTier Tier
	UserTier     Tier
	Decision     string // "PASS" or "FAIL"
	Timestamp    time.Time
	TargetID     string
	DeletedItems map[string]int
}

var (
	auditLog []AuditEntry
	auditMu  sync.Mutex
)

func logAudit(entry AuditEntry) {
	auditMu.Lock()
	defer auditMu.Unlock()
	auditLog = append(auditLog, entry)
}

// GetAuditLog returns a copy of the audit log (for tests)
func GetAuditLog() []AuditEntry {
	auditMu.Lock()
	defer auditMu.Unlock()
	cpy := make([]AuditEntry, len(auditLog))
	copy(cpy, auditLog)
	return cpy
}

// ---------- Helper: tier hierarchy ----------
var tierRank = map[Tier]int{
	TierPublic:  0,
	TierMember:  1,
	TierAdmin:   2,
	TierOwner:   3,
	TierService: 4, // service is considered highest for internal use
}

// hasAtLeast returns true if userTier >= requiredTier in the hierarchy.
func hasAtLeast(userTier, requiredTier Tier) bool {
	return tierRank[userTier] >= tierRank[requiredTier]
}

// ---------- Middleware ----------
func RequireOwner(user *User, endpoint string) error {
	if user == nil {
		logAudit(AuditEntry{
			Action:       "permission_check",
			UserID:       "",
			Endpoint:     endpoint,
			RequiredTier: TierOwner,
			UserTier:     "",
			Decision:     "FAIL",
			Timestamp:    time.Now(),
		})
		return &RBACError{Code: 401, Message: "authentication_required"}
	}
	if user.Tier != TierOwner {
		logAudit(AuditEntry{
			Action:       "permission_check",
			UserID:       user.ID,
			Endpoint:     endpoint,
			RequiredTier: TierOwner,
			UserTier:     user.Tier,
			Decision:     "FAIL",
			Timestamp:    time.Now(),
		})
		return &RBACError{Code: 403, Message: "owner_only"}
	}
	logAudit(AuditEntry{
		Action:       "permission_check",
		UserID:       user.ID,
		Endpoint:     endpoint,
		RequiredTier: TierOwner,
		UserTier:     user.Tier,
		Decision:     "PASS",
		Timestamp:    time.Now(),
	})
	return nil
}

func RequireAdmin(user *User, endpoint string) error {
	if user == nil {
		logAudit(AuditEntry{
			Action:       "permission_check",
			UserID:       "",
			Endpoint:     endpoint,
			RequiredTier: TierAdmin,
			UserTier:     "",
			Decision:     "FAIL",
			Timestamp:    time.Now(),
		})
		return &RBACError{Code: 401, Message: "authentication_required"}
	}
	if !hasAtLeast(user.Tier, TierAdmin) {
		logAudit(AuditEntry{
			Action:       "permission_check",
			UserID:       user.ID,
			Endpoint:     endpoint,
			RequiredTier: TierAdmin,
			UserTier:     user.Tier,
			Decision:     "FAIL",
			Timestamp:    time.Now(),
		})
		return &RBACError{Code: 403, Message: "admin_only"}
	}
	logAudit(AuditEntry{
		Action:       "permission_check",
		UserID:       user.ID,
		Endpoint:     endpoint,
		RequiredTier: TierAdmin,
		UserTier:     user.Tier,
		Decision:     "PASS",
		Timestamp:    time.Now(),
	})
	return nil
}

func RequireAuthenticated(user *User, endpoint string) error {
	if user == nil {
		logAudit(AuditEntry{
			Action:       "permission_check",
			UserID:       "",
			Endpoint:     endpoint,
			RequiredTier: TierPublic,
			UserTier:     "",
			Decision:     "FAIL",
			Timestamp:    time.Now(),
		})
		return &RBACError{Code: 401, Message: "authentication_required"}
	}
	// any authenticated tier passes
	logAudit(AuditEntry{
		Action:       "permission_check",
		UserID:       user.ID,
		Endpoint:     endpoint,
		RequiredTier: TierPublic,
		UserTier:     user.Tier,
		Decision:     "PASS",
		Timestamp:    time.Now(),
	})
	return nil
}

// ---------- In‑memory data store ----------
type Session struct{ ID, UserID string }

// APIKey is an API key row. OrgID "" is a personal key, which belongs to its user and survives an
// org deletion (spec RBAC-06). OrgID added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
type APIKey struct{ ID, UserID, OrgID string }

// Membership is one (org_id, user_id, role) row as in organizations_teams.md; role is owner, admin or
// member. Invitation is a pending invitation to an org. Both added 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP: the org cascade gates on the caller's membership role and deletes
// the org's memberships and invitations, never user accounts (RBAC-06).
type Membership struct {
	OrgID, UserID string
	Role          Tier
}
type Invitation struct{ ID, OrgID, Email string }
type File struct{ ID, OwnerID string }
type Preference struct{ ID, UserID string }

type Deployment struct{ ID, OrgID string }
type DNSRecord struct{ ID, DeploymentID string }
type ThemeConfig struct{ ID, DeploymentID string }
type DeploymentLog struct{ ID, DeploymentID string }

type Organization struct{ ID string }

var (
	usersMu          sync.RWMutex
	users            = make(map[string]*User)
	sessionsMu       sync.RWMutex
	sessions         = make(map[string]*Session)
	apiKeysMu        sync.RWMutex
	apiKeys          = make(map[string]*APIKey)
	filesMu          sync.RWMutex
	files            = make(map[string]*File)
	prefsMu          sync.RWMutex
	preferences      = make(map[string]*Preference)
	deploymentsMu    sync.RWMutex
	deployments      = make(map[string]*Deployment)
	dnsRecordsMu     sync.RWMutex
	dnsRecords       = make(map[string]*DNSRecord)
	themeConfigsMu   sync.RWMutex
	themeConfigs     = make(map[string]*ThemeConfig)
	deploymentLogsMu sync.RWMutex
	deploymentLogs   = make(map[string]*DeploymentLog)
	orgsMu           sync.RWMutex
	organizations    = make(map[string]*Organization)
	membershipsMu    sync.RWMutex
	memberships      = make(map[string]*Membership) // key: membershipKey(org_id, user_id)
	invitationsMu    sync.RWMutex
	invitations      = make(map[string]*Invitation)

	// For testing error injection in cascade operations
	cascadeInjectError bool
)

// ---------- Transaction helpers ----------
type backupState struct {
	users          map[string]*User
	sessions       map[string]*Session
	apiKeys        map[string]*APIKey
	files          map[string]*File
	preferences    map[string]*Preference
	deployments    map[string]*Deployment
	dnsRecords     map[string]*DNSRecord
	themeConfigs   map[string]*ThemeConfig
	deploymentLogs map[string]*DeploymentLog
	organizations  map[string]*Organization
	memberships    map[string]*Membership
	invitations    map[string]*Invitation
}

func takeBackup() backupState {
	usersMu.RLock()
	sessionsMu.RLock()
	apiKeysMu.RLock()
	filesMu.RLock()
	prefsMu.RLock()
	deploymentsMu.RLock()
	dnsRecordsMu.RLock()
	themeConfigsMu.RLock()
	deploymentLogsMu.RLock()
	orgsMu.RLock()
	membershipsMu.RLock()
	invitationsMu.RLock()
	defer func() {
		membershipsMu.RUnlock()
		invitationsMu.RUnlock()
		usersMu.RUnlock()
		sessionsMu.RUnlock()
		apiKeysMu.RUnlock()
		filesMu.RUnlock()
		prefsMu.RUnlock()
		deploymentsMu.RUnlock()
		dnsRecordsMu.RUnlock()
		themeConfigsMu.RUnlock()
		deploymentLogsMu.RUnlock()
		orgsMu.RUnlock()
	}()

	// shallow copy (values are pointers, but we never modify the pointed structs)
	b := backupState{
		users:          make(map[string]*User, len(users)),
		sessions:       make(map[string]*Session, len(sessions)),
		apiKeys:        make(map[string]*APIKey, len(apiKeys)),
		files:          make(map[string]*File, len(files)),
		preferences:    make(map[string]*Preference, len(preferences)),
		deployments:    make(map[string]*Deployment, len(deployments)),
		dnsRecords:     make(map[string]*DNSRecord, len(dnsRecords)),
		themeConfigs:   make(map[string]*ThemeConfig, len(themeConfigs)),
		deploymentLogs: make(map[string]*DeploymentLog, len(deploymentLogs)),
		organizations:  make(map[string]*Organization, len(organizations)),
		memberships:    make(map[string]*Membership, len(memberships)),
		invitations:    make(map[string]*Invitation, len(invitations)),
	}
	for k, v := range users { b.users[k] = v }
	for k, v := range sessions { b.sessions[k] = v }
	for k, v := range apiKeys { b.apiKeys[k] = v }
	for k, v := range files { b.files[k] = v }
	for k, v := range preferences { b.preferences[k] = v }
	for k, v := range deployments { b.deployments[k] = v }
	for k, v := range dnsRecords { b.dnsRecords[k] = v }
	for k, v := range themeConfigs { b.themeConfigs[k] = v }
	for k, v := range deploymentLogs { b.deploymentLogs[k] = v }
	for k, v := range organizations { b.organizations[k] = v }
	for k, v := range memberships { b.memberships[k] = v }
	for k, v := range invitations { b.invitations[k] = v }
	return b
}

func restoreBackup(b backupState) {
	usersMu.Lock()
	sessionsMu.Lock()
	apiKeysMu.Lock()
	filesMu.Lock()
	prefsMu.Lock()
	deploymentsMu.Lock()
	dnsRecordsMu.Lock()
	themeConfigsMu.Lock()
	deploymentLogsMu.Lock()
	orgsMu.Lock()
	membershipsMu.Lock()
	invitationsMu.Lock()
	defer func() {
		membershipsMu.Unlock()
		invitationsMu.Unlock()
		usersMu.Unlock()
		sessionsMu.Unlock()
		apiKeysMu.Unlock()
		filesMu.Unlock()
		prefsMu.Unlock()
		deploymentsMu.Unlock()
		dnsRecordsMu.Unlock()
		themeConfigsMu.Unlock()
		deploymentLogsMu.Unlock()
		orgsMu.Unlock()
	}()

	users = b.users
	sessions = b.sessions
	apiKeys = b.apiKeys
	files = b.files
	preferences = b.preferences
	deployments = b.deployments
	dnsRecords = b.dnsRecords
	themeConfigs = b.themeConfigs
	deploymentLogs = b.deploymentLogs
	organizations = b.organizations
	memberships = b.memberships
	invitations = b.invitations
}

// ---------- Cascade delete implementations ----------
func DeleteUser(userID string) error {
	backup := takeBackup()
	defer func() {
		if r := recover(); r != nil {
			restoreBackup(backup)
		}
	}()

	// Delete user
	usersMu.Lock()
	if _, ok := users[userID]; !ok {
		usersMu.Unlock()
		restoreBackup(backup)
		return errors.New("user not found")
	}
	delete(users, userID)
	usersMu.Unlock()

	// Delete sessions
	sessionsMu.Lock()
	for sid, s := range sessions {
		if s.UserID == userID {
			delete(sessions, sid)
		}
	}
	sessionsMu.Unlock()

	// Delete API keys
	apiKeysMu.Lock()
	for kid, k := range apiKeys {
		if k.UserID == userID {
			delete(apiKeys, kid)
		}
	}
	apiKeysMu.Unlock()

	// Delete files
	filesMu.Lock()
	for fid, f := range files {
		if f.OwnerID == userID {
			delete(files, fid)
		}
	}
	filesMu.Unlock()

	// Delete preferences
	prefsMu.Lock()
	for pid, p := range preferences {
		if p.UserID == userID {
			delete(preferences, pid)
		}
	}
	prefsMu.Unlock()

	// Simulated error injection
	if cascadeInjectError {
		restoreBackup(backup)
		return errors.New("simulated cascade error")
	}

	// Log audit
	logAudit(AuditEntry{
		Action:    "user_deleted_cascade",
		UserID:    userID,
		Endpoint:  "DeleteUser",
		Decision:  "PASS",
		Timestamp: time.Now(),
	})
	return nil
}

func DeleteDeployment(deploymentID string) error {
	backup := takeBackup()
	defer func() {
		if r := recover(); r != nil {
			restoreBackup(backup)
		}
	}()

	// Delete deployment
	deploymentsMu.Lock()
	if _, ok := deployments[deploymentID]; !ok {
		deploymentsMu.Unlock()
		restoreBackup(backup)
		return errors.New("deployment not found")
	}
	delete(deployments, deploymentID)
	deploymentsMu.Unlock()

	// Delete DNS records
	dnsRecordsMu.Lock()
	for id, r := range dnsRecords {
		if r.DeploymentID == deploymentID {
			delete(dnsRecords, id)
		}
	}
	dnsRecordsMu.Unlock()

	// Delete theme configs
	themeConfigsMu.Lock()
	for id, c := range themeConfigs {
		if c.DeploymentID == deploymentID {
			delete(themeConfigs, id)
		}
	}
	themeConfigsMu.Unlock()

	// Delete deployment logs
	deploymentLogsMu.Lock()
	for id, l := range deploymentLogs {
		if l.DeploymentID == deploymentID {
			delete(deploymentLogs, id)
		}
	}
	deploymentLogsMu.Unlock()

	if cascadeInjectError {
		restoreBackup(backup)
		return errors.New("simulated cascade error")
	}

	logAudit(AuditEntry{
		Action:    "deployment_deleted_cascade",
		UserID:    "", // system action
		Endpoint:  "DeleteDeployment",
		Decision:  "PASS",
		Timestamp: time.Now(),
	})
	return nil
}

// membershipKey is the map key of a membership row (org_id, user_id).
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
func membershipKey(orgID, userID string) string { return orgID + "\x00" + userID }

// AddMembership stores a membership row (org_id, user_id, role). In: the org, the user and the role
// (owner, admin or member). Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory.
func AddMembership(orgID, userID string, role Tier) {
	membershipsMu.Lock()
	defer membershipsMu.Unlock()
	memberships[membershipKey(orgID, userID)] = &Membership{OrgID: orgID, UserID: userID, Role: role}
}

// GetMembership returns the membership row of (org_id, user_id), if any.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
func GetMembership(orgID, userID string) (*Membership, bool) {
	membershipsMu.RLock()
	defer membershipsMu.RUnlock()
	m, ok := memberships[membershipKey(orgID, userID)]
	return m, ok
}

// GetInvitation returns an invitation by id, if any.
// Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory (read).
func GetInvitation(id string) (*Invitation, bool) {
	invitationsMu.RLock()
	defer invitationsMu.RUnlock()
	i, ok := invitations[id]
	return i, ok
}

// DeleteOrganization deletes an organization and everything that belongs to it, all or nothing.
//
// In: the verified caller and the org id. Out: nil, or *RBACError 401 authentication_required (no
// caller), 404 not_found (the org does not exist, or the caller's membership row for it is not
// 'owner': a global admin or owner tier is not enough), or the simulated cascade error (rolled back).
// Deletes: the org's deployments, each with the deployment cascade (DNS records, theme configs,
// deployment logs); API keys whose OrgID is this org; all its invitations and membership rows; the org.
// Keeps: every user account, session and personal API key (OrgID ""), and every membership of
// another org, because a user may belong to several orgs. Logs org_deleted_cascade with
// deleted_items {deployments, api_keys, invitations, memberships}.
// Why: spec RBAC-06 (amended 2026-11-10 after review on PR 19). The old Go code took no caller and
// deleted every user whose id began with "<org id>-" together with their sessions and keys.
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the in-memory store, the audit log.
func DeleteOrganization(caller *User, orgID string) error {
	if caller == nil {
		return &RBACError{Code: 401, Message: "authentication_required"}
	}
	m, isMember := GetMembership(orgID, caller.ID)
	_, orgExists := GetOrganization(orgID)
	if !orgExists || !isMember || m.Role != TierOwner {
		logAudit(AuditEntry{Action: "permission_check", UserID: caller.ID, Endpoint: "DeleteOrganization",
			RequiredTier: TierOwner, UserTier: caller.Tier, Decision: "FAIL", Timestamp: time.Now(), TargetID: orgID})
		return &RBACError{Code: 404, Message: "not_found"}
	}

	backup := takeBackup()
	defer func() {
		if r := recover(); r != nil {
			restoreBackup(backup)
			panic(r)
		}
	}()
	counts := map[string]int{"deployments": 0, "api_keys": 0, "invitations": 0, "memberships": 0}

	orgsMu.Lock()
	delete(organizations, orgID)
	orgsMu.Unlock()

	deploymentsMu.Lock()
	depIDs := map[string]bool{}
	for id, d := range deployments {
		if d.OrgID == orgID {
			depIDs[id] = true
			delete(deployments, id)
		}
	}
	deploymentsMu.Unlock()
	counts["deployments"] = len(depIDs)

	dnsRecordsMu.Lock()
	for id, r := range dnsRecords {
		if depIDs[r.DeploymentID] {
			delete(dnsRecords, id)
		}
	}
	dnsRecordsMu.Unlock()
	themeConfigsMu.Lock()
	for id, c := range themeConfigs {
		if depIDs[c.DeploymentID] {
			delete(themeConfigs, id)
		}
	}
	themeConfigsMu.Unlock()
	deploymentLogsMu.Lock()
	for id, l := range deploymentLogs {
		if depIDs[l.DeploymentID] {
			delete(deploymentLogs, id)
		}
	}
	deploymentLogsMu.Unlock()

	apiKeysMu.Lock()
	for kid, k := range apiKeys {
		if k.OrgID != "" && k.OrgID == orgID {
			delete(apiKeys, kid)
			counts["api_keys"]++
		}
	}
	apiKeysMu.Unlock()

	invitationsMu.Lock()
	for id, inv := range invitations {
		if inv.OrgID == orgID {
			delete(invitations, id)
			counts["invitations"]++
		}
	}
	invitationsMu.Unlock()

	membershipsMu.Lock()
	for k, mem := range memberships {
		if mem.OrgID == orgID {
			delete(memberships, k)
			counts["memberships"]++
		}
	}
	membershipsMu.Unlock()

	if cascadeInjectError {
		restoreBackup(backup)
		return errors.New("simulated cascade error")
	}

	logAudit(AuditEntry{
		Action:       "org_deleted_cascade",
		UserID:       caller.ID,
		Endpoint:     "DeleteOrganization",
		Decision:     "PASS",
		Timestamp:    time.Now(),
		TargetID:     orgID,
		DeletedItems: counts,
	})
	return nil
}

// ---------- Helper functions for tests ----------
func ResetAllData() {
	usersMu.Lock()
	sessionsMu.Lock()
	apiKeysMu.Lock()
	filesMu.Lock()
	prefsMu.Lock()
	deploymentsMu.Lock()
	dnsRecordsMu.Lock()
	themeConfigsMu.Lock()
	deploymentLogsMu.Lock()
	orgsMu.Lock()
	membershipsMu.Lock()
	invitationsMu.Lock()
	defer func() {
		membershipsMu.Unlock()
		invitationsMu.Unlock()
		usersMu.Unlock()
		sessionsMu.Unlock()
		apiKeysMu.Unlock()
		filesMu.Unlock()
		prefsMu.Unlock()
		deploymentsMu.Unlock()
		dnsRecordsMu.Unlock()
		themeConfigsMu.Unlock()
		deploymentLogsMu.Unlock()
		orgsMu.Unlock()
	}()

	users = make(map[string]*User)
	sessions = make(map[string]*Session)
	apiKeys = make(map[string]*APIKey)
	files = make(map[string]*File)
	preferences = make(map[string]*Preference)
	deployments = make(map[string]*Deployment)
	dnsRecords = make(map[string]*DNSRecord)
	themeConfigs = make(map[string]*ThemeConfig)
	deploymentLogs = make(map[string]*DeploymentLog)
	organizations = make(map[string]*Organization)
	memberships = make(map[string]*Membership)
	invitations = make(map[string]*Invitation)

	auditMu.Lock()
	auditLog = nil
	auditMu.Unlock()

	cascadeInjectError = false
}

// ---------- Exported for tests ----------
func SetCascadeInjectError(v bool) {
	cascadeInjectError = v
}

// ---------- Simple getters for verification ----------
func GetUser(id string) (*User, bool) {
	usersMu.RLock()
	defer usersMu.RUnlock()
	u, ok := users[id]
	return u, ok
}
func GetSession(id string) (*Session, bool) {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	s, ok := sessions[id]
	return s, ok
}
func GetAPIKey(id string) (*APIKey, bool) {
	apiKeysMu.RLock()
	defer apiKeysMu.RUnlock()
	k, ok := apiKeys[id]
	return k, ok
}
func GetFile(id string) (*File, bool) {
	filesMu.RLock()
	defer filesMu.RUnlock()
	f, ok := files[id]
	return f, ok
}
func GetPreference(id string) (*Preference, bool) {
	prefsMu.RLock()
	defer prefsMu.RUnlock()
	p, ok := preferences[id]
	return p, ok
}
func GetDeployment(id string) (*Deployment, bool) {
	deploymentsMu.RLock()
	defer deploymentsMu.RUnlock()
	d, ok := deployments[id]
	return d, ok
}
func GetDNSRecord(id string) (*DNSRecord, bool) {
	dnsRecordsMu.RLock()
	defer dnsRecordsMu.RUnlock()
	r, ok := dnsRecords[id]
	return r, ok
}
func GetThemeConfig(id string) (*ThemeConfig, bool) {
	themeConfigsMu.RLock()
	defer themeConfigsMu.RUnlock()
	c, ok := themeConfigs[id]
	return c, ok
}
func GetDeploymentLog(id string) (*DeploymentLog, bool) {
	deploymentLogsMu.RLock()
	defer deploymentLogsMu.RUnlock()
	l, ok := deploymentLogs[id]
	return l, ok
}
func GetOrganization(id string) (*Organization, bool) {
	orgsMu.RLock()
	defer orgsMu.RUnlock()
	o, ok := organizations[id]
	return o, ok
}