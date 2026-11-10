package organizations_teams

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// Role represents a membership role within an organization.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// User represents a user in the system.
type User struct {
	ID    string
	Email string
}

// Org represents an organization.
type Org struct {
	ID      string
	Name    string
	Slug    string
	Creator User
}

// Membership represents a user's membership in an organization.
type Membership struct {
	OrgID   string
	UserID  string
	Role    Role
	Email   string
}

// Invitation represents an invitation to join an organization.
type Invitation struct {
	ID         string
	OrgID      string
	Email      string
	Role       Role
	TokenHash  string
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	InvitedBy  string
	CreatedAt  time.Time
}

// Store defines the storage interface for organizations and teams.
type Store interface {
	CreateOrg(org Org) error
	GetOrgBySlug(slug string) (Org, error)
	GetOrgByID(orgID string) (Org, error)
	CreateMembership(membership Membership) error
	GetMembership(orgID, userID string) (Membership, error)
	UpdateMembershipRole(orgID, userID string, role Role) error
	DeleteMembership(orgID, userID string) error
	ListMemberships(orgID string) ([]Membership, error)
	CountOwners(orgID string) (int, error)
	CreateInvitation(invitation Invitation) error
	GetInvitationByTokenHash(tokenHash string) (Invitation, error)
	UpdateInvitation(invitation Invitation) error
}

// InMemoryStore is an in-memory implementation of the Store interface.
type InMemoryStore struct {
	orgs          map[string]Org
	memberships   map[string]map[string]Membership // orgID -> userID -> Membership
	invitations   map[string]Invitation            // tokenHash -> Invitation
	orgCounter    int
	invCounter    int
}

// NewInMemoryStore creates a new in-memory store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		orgs:        make(map[string]Org),
		memberships: make(map[string]map[string]Membership),
		invitations: make(map[string]Invitation),
	}
}

func (s *InMemoryStore) CreateOrg(org Org) error {
	if _, exists := s.orgs[org.ID]; exists {
		return errors.New("organization already exists")
	}
	s.orgs[org.ID] = org
	return nil
}

func (s *InMemoryStore) GetOrgBySlug(slug string) (Org, error) {
	for _, org := range s.orgs {
		if org.Slug == slug {
			return org, nil
		}
	}
	return Org{}, errors.New("organization not found")
}

func (s *InMemoryStore) GetOrgByID(orgID string) (Org, error) {
	org, exists := s.orgs[orgID]
	if !exists {
		return Org{}, errors.New("organization not found")
	}
	return org, nil
}

func (s *InMemoryStore) CreateMembership(membership Membership) error {
	if _, exists := s.memberships[membership.OrgID]; !exists {
		s.memberships[membership.OrgID] = make(map[string]Membership)
	}
	if _, exists := s.memberships[membership.OrgID][membership.UserID]; exists {
		return errors.New("membership already exists")
	}
	s.memberships[membership.OrgID][membership.UserID] = membership
	return nil
}

func (s *InMemoryStore) GetMembership(orgID, userID string) (Membership, error) {
	if orgMembers, exists := s.memberships[orgID]; exists {
		if membership, exists := orgMembers[userID]; exists {
			return membership, nil
		}
	}
	return Membership{}, errors.New("membership not found")
}

func (s *InMemoryStore) UpdateMembershipRole(orgID, userID string, role Role) error {
	if orgMembers, exists := s.memberships[orgID]; exists {
		if membership, exists := orgMembers[userID]; exists {
			membership.Role = role
			orgMembers[userID] = membership
			return nil
		}
	}
	return errors.New("membership not found")
}

func (s *InMemoryStore) DeleteMembership(orgID, userID string) error {
	if orgMembers, exists := s.memberships[orgID]; exists {
		if _, exists := orgMembers[userID]; exists {
			delete(orgMembers, userID)
			return nil
		}
	}
	return errors.New("membership not found")
}

func (s *InMemoryStore) ListMemberships(orgID string) ([]Membership, error) {
	if orgMembers, exists := s.memberships[orgID]; exists {
		members := make([]Membership, 0, len(orgMembers))
		for _, membership := range orgMembers {
			members = append(members, membership)
		}
		return members, nil
	}
	return []Membership{}, nil
}

func (s *InMemoryStore) CountOwners(orgID string) (int, error) {
	count := 0
	if orgMembers, exists := s.memberships[orgID]; exists {
		for _, membership := range orgMembers {
			if membership.Role == RoleOwner {
				count++
			}
		}
	}
	return count, nil
}

func (s *InMemoryStore) CreateInvitation(invitation Invitation) error {
	s.invitations[invitation.TokenHash] = invitation
	return nil
}

func (s *InMemoryStore) GetInvitationByTokenHash(tokenHash string) (Invitation, error) {
	invitation, exists := s.invitations[tokenHash]
	if !exists {
		return Invitation{}, errors.New("invitation not found")
	}
	return invitation, nil
}

func (s *InMemoryStore) UpdateInvitation(invitation Invitation) error {
	if _, exists := s.invitations[invitation.TokenHash]; !exists {
		return errors.New("invitation not found")
	}
	s.invitations[invitation.TokenHash] = invitation
	return nil
}

// SQLStore is a SQL implementation of the Store interface.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a new SQL store.
func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateOrg(org Org) error {
	_, err := s.db.Exec("INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)",
		org.ID, org.Name, org.Slug, time.Now())
	return err
}

func (s *SQLStore) GetOrgBySlug(slug string) (Org, error) {
	var org Org
	err := s.db.QueryRow("SELECT id, name, slug FROM organizations WHERE slug = ?", slug).Scan(&org.ID, &org.Name, &org.Slug)
	if err != nil {
		return Org{}, errors.New("organization not found")
	}
	return org, nil
}

func (s *SQLStore) GetOrgByID(orgID string) (Org, error) {
	var org Org
	err := s.db.QueryRow("SELECT id, name, slug FROM organizations WHERE id = ?", orgID).Scan(&org.ID, &org.Name, &org.Slug)
	if err != nil {
		return Org{}, errors.New("organization not found")
	}
	return org, nil
}

func (s *SQLStore) CreateMembership(membership Membership) error {
	_, err := s.db.Exec("INSERT INTO memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
		membership.OrgID, membership.UserID, membership.Role, time.Now())
	return err
}

func (s *SQLStore) GetMembership(orgID, userID string) (Membership, error) {
	var membership Membership
	err := s.db.QueryRow("SELECT org_id, user_id, role FROM memberships WHERE org_id = ? AND user_id = ?", orgID, userID).
		Scan(&membership.OrgID, &membership.UserID, &membership.Role)
	if err != nil {
		return Membership{}, errors.New("membership not found")
	}
	return membership, nil
}

func (s *SQLStore) UpdateMembershipRole(orgID, userID string, role Role) error {
	result, err := s.db.Exec("UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?", role, orgID, userID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("membership not found")
	}
	return nil
}

func (s *SQLStore) DeleteMembership(orgID, userID string) error {
	result, err := s.db.Exec("DELETE FROM memberships WHERE org_id = ? AND user_id = ?", orgID, userID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("membership not found")
	}
	return nil
}

func (s *SQLStore) ListMemberships(orgID string) ([]Membership, error) {
	rows, err := s.db.Query("SELECT org_id, user_id, role FROM memberships WHERE org_id = ?", orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []Membership
	for rows.Next() {
		var membership Membership
		err := rows.Scan(&membership.OrgID, &membership.UserID, &membership.Role)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, membership)
	}
	return memberships, nil
}

func (s *SQLStore) CountOwners(orgID string) (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM memberships WHERE org_id = ? AND role = 'owner'", orgID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLStore) CreateInvitation(invitation Invitation) error {
	_, err := s.db.Exec("INSERT INTO invitations (id, org_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		invitation.ID, invitation.OrgID, invitation.Email, invitation.Role, invitation.TokenHash, invitation.ExpiresAt, invitation.AcceptedAt, invitation.InvitedBy, invitation.CreatedAt)
	return err
}

func (s *SQLStore) GetInvitationByTokenHash(tokenHash string) (Invitation, error) {
	var invitation Invitation
	err := s.db.QueryRow("SELECT id, org_id, email, role, token_hash, expires_at, accepted_at, invited_by, created_at FROM invitations WHERE token_hash = ?", tokenHash).
		Scan(&invitation.ID, &invitation.OrgID, &invitation.Email, &invitation.Role, &invitation.TokenHash, &invitation.ExpiresAt, &invitation.AcceptedAt, &invitation.InvitedBy, &invitation.CreatedAt)
	if err != nil {
		return Invitation{}, errors.New("invitation not found")
	}
	return invitation, nil
}

func (s *SQLStore) UpdateInvitation(invitation Invitation) error {
	_, err := s.db.Exec("UPDATE invitations SET accepted_at = ? WHERE token_hash = ?", invitation.AcceptedAt, invitation.TokenHash)
	return err
}

// OrganizationsTeams is the main service for managing organizations and teams.
type OrganizationsTeams struct {
	store Store
}

// NewOrganizationsTeams creates a new OrganizationsTeams service.
func NewOrganizationsTeams(store Store) *OrganizationsTeams {
	return &OrganizationsTeams{store: store}
}

// generateID generates a unique ID.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateToken generates a random token and returns the raw token and its hash.
func generateToken() (string, string) {
	b := make([]byte, 32)
	rand.Read(b)
	rawToken := hex.EncodeToString(b)
	hash := sha256.Sum256(b)
	return rawToken, hex.EncodeToString(hash[:])
}

// hashToken hashes a raw token using SHA-256.
func hashToken(rawToken string) string {
	b, _ := hex.DecodeString(rawToken)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// CreateOrg creates a new organization with the given user as the owner.
func (o *OrganizationsTeams) CreateOrg(user User, name string) (Org, error) {
	slug := name
	org := Org{
		ID:      generateID(),
		Name:    name,
		Slug:    slug,
		Creator: user,
	}
	err := o.store.CreateOrg(org)
	if err != nil {
		return Org{}, err
	}
	membership := Membership{
		OrgID:  org.ID,
		UserID: user.ID,
		Role:   RoleOwner,
		Email:  user.Email,
	}
	err = o.store.CreateMembership(membership)
	if err != nil {
		return Org{}, err
	}
	return org, nil
}

// Invite invites a user to join an organization by email.
//
// In: the verified actor, the org id, the invitee's email and role. Out: the raw token (returned once;
// only its SHA-256 hash is stored), or "not found" / "forbidden" / "invalid role".
// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: only an owner may invite with role owner (spec
// "Least privilege"). Touches: the invitations store; crypto/rand.
func (o *OrganizationsTeams) Invite(actor User, orgID, email string, role Role) (string, error) {
	// Check if actor is a member of the org
	membership, err := o.store.GetMembership(orgID, actor.ID)
	if err != nil {
		return "", errors.New("not found")
	}
	// Check if actor has permission to invite (admin or owner)
	if membership.Role != RoleAdmin && membership.Role != RoleOwner {
		return "", errors.New("forbidden")
	}
	// Validate role
	if role != RoleOwner && role != RoleAdmin && role != RoleMember {
		return "", errors.New("invalid role")
	}
	// Only an owner may grant the owner role (spec "Least privilege", amended 2026-09-26; fixed in Go
	// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: an admin could invite a second owner).
	if role == RoleOwner && membership.Role != RoleOwner {
		return "", errors.New("forbidden")
	}
	// Generate token
	rawToken, tokenHash := generateToken()
	invitation := Invitation{
		ID:        generateID(),
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		InvitedBy: actor.ID,
		CreatedAt: time.Now(),
	}
	err = o.store.CreateInvitation(invitation)
	if err != nil {
		return "", err
	}
	return rawToken, nil
}

// AcceptInvitation accepts an invitation and creates a membership.
func (o *OrganizationsTeams) AcceptInvitation(user User, rawToken string) (Membership, error) {
	tokenHash := hashToken(rawToken)
	invitation, err := o.store.GetInvitationByTokenHash(tokenHash)
	if err != nil {
		return Membership{}, errors.New("not found")
	}
	// Check if invitation is expired
	if time.Now().After(invitation.ExpiresAt) {
		return Membership{}, errors.New("invitation expired")
	}
	// Check if invitation has already been accepted
	if invitation.AcceptedAt != nil {
		return Membership{}, errors.New("invitation already accepted")
	}
	// Check if the user's email matches the invitation email
	if user.Email != invitation.Email {
		return Membership{}, errors.New("email mismatch")
	}
	// Create membership
	membership := Membership{
		OrgID:  invitation.OrgID,
		UserID: user.ID,
		Role:   invitation.Role,
		Email:  user.Email,
	}
	err = o.store.CreateMembership(membership)
	if err != nil {
		return Membership{}, err
	}
	// Mark invitation as accepted
	now := time.Now()
	invitation.AcceptedAt = &now
	err = o.store.UpdateInvitation(invitation)
	if err != nil {
		return Membership{}, err
	}
	return membership, nil
}

// ChangeRole changes the role of an existing member of an organization.
//
// In: the verified actor, the org id, the target user id and the new role. Out: nil, or an error
// "not found" (actor or target not a member), "forbidden" (a member acting, an admin touching an owner,
// or a non-owner granting owner), "invalid role", or "cannot demote the last owner".
// Why: organizations_teams spec "Least privilege": an admin manages members but cannot demote or change
// the owner, and only an owner grants the owner role. Before 2026-11-10 only owners could change roles
// at all. Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the memberships store.
func (o *OrganizationsTeams) ChangeRole(actor User, orgID, userID string, role Role) error {
	actorMembership, err := o.store.GetMembership(orgID, actor.ID)
	if err != nil {
		return errors.New("not found")
	}
	if actorMembership.Role != RoleOwner && actorMembership.Role != RoleAdmin {
		return errors.New("forbidden")
	}
	targetMembership, err := o.store.GetMembership(orgID, userID)
	if err != nil {
		return errors.New("not found")
	}
	if role != RoleOwner && role != RoleAdmin && role != RoleMember {
		return errors.New("invalid role")
	}
	if actorMembership.Role != RoleOwner && (targetMembership.Role == RoleOwner || role == RoleOwner) {
		return errors.New("forbidden")
	}
	if targetMembership.Role == RoleOwner && role != RoleOwner {
		ownerCount, err := o.store.CountOwners(orgID)
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return errors.New("cannot demote the last owner")
		}
	}
	return o.store.UpdateMembershipRole(orgID, userID, role)
}

// RemoveMember removes an existing member from an organization.
//
// In: the verified actor, the org id and the target user id. Out: nil, or "not found" (actor or target
// not a member), "forbidden" (a member acting, or an admin removing an owner), or "cannot remove the
// last owner".
// Why: organizations_teams spec "Least privilege" (ORG-03): an admin manages members but cannot remove
// the owner. Before 2026-11-10 only owners could remove anyone. Changed 2026-11-10,
// session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the memberships store.
func (o *OrganizationsTeams) RemoveMember(actor User, orgID, userID string) error {
	actorMembership, err := o.store.GetMembership(orgID, actor.ID)
	if err != nil {
		return errors.New("not found")
	}
	if actorMembership.Role != RoleOwner && actorMembership.Role != RoleAdmin {
		return errors.New("forbidden")
	}
	targetMembership, err := o.store.GetMembership(orgID, userID)
	if err != nil {
		return errors.New("not found")
	}
	if targetMembership.Role == RoleOwner {
		if actorMembership.Role != RoleOwner {
			return errors.New("forbidden")
		}
		ownerCount, err := o.store.CountOwners(orgID)
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return errors.New("cannot remove the last owner")
		}
	}
	return o.store.DeleteMembership(orgID, userID)
}

// LeaveOrg allows a user to leave an organization.
func (o *OrganizationsTeams) LeaveOrg(user User, orgID string) error {
	// Check if user is a member of the org
	membership, err := o.store.GetMembership(orgID, user.ID)
	if err != nil {
		return errors.New("not found")
	}
	// Check if user is the owner
	if membership.Role == RoleOwner {
		// Check if this would leave the org with no owners
		ownerCount, err := o.store.CountOwners(orgID)
		if err != nil {
			return err
		}
		if ownerCount <= 1 {
			return errors.New("cannot leave as the last owner")
		}
	}
	return o.store.DeleteMembership(orgID, user.ID)
}

// ListMembers lists all members of an organization.
func (o *OrganizationsTeams) ListMembers(actor User, orgID string) ([]Membership, error) {
	// Check if actor is a member of the org
	_, err := o.store.GetMembership(orgID, actor.ID)
	if err != nil {
		return nil, errors.New("not found")
	}
	return o.store.ListMemberships(orgID)
}

// GetOrg retrieves an organization by ID.
func (o *OrganizationsTeams) GetOrg(actor User, orgID string) (Org, error) {
	// Check if actor is a member of the org
	_, err := o.store.GetMembership(orgID, actor.ID)
	if err != nil {
		return Org{}, errors.New("not found")
	}
	return o.store.GetOrgByID(orgID)
}