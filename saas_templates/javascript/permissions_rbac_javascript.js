const db = {
  users: [],
  sessions: [],
  apiKeys: [],
  files: [],
  preferences: [],
  deployments: [],
  dnsRecords: [],
  themeConfigs: [],
  deploymentLogs: [],
  organizations: [],
  memberships: [],   // { orgId, userId, role } as in organizations_teams.md (2026-11-10, RBAC-06)
  invitations: [],   // { id, orgId, email, ... } (2026-11-10, RBAC-06)
  auditLog: []
};

const ddl = `
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  tier VARCHAR(20) NOT NULL CHECK (tier IN ('public', 'member', 'admin', 'owner')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE api_keys (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  org_id INTEGER NULL REFERENCES organizations(id),  -- NULL = a personal key (kept when an org is deleted)
  key VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE files (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  size INTEGER,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE preferences (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  theme VARCHAR(50),
  notifications BOOLEAN DEFAULT true,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE organizations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE memberships (
  org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(20) NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  PRIMARY KEY (org_id, user_id)
);
CREATE TABLE invitations (
  id SERIAL PRIMARY KEY,
  org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  token_hash CHAR(64) NOT NULL
);
CREATE TABLE deployments (
  id SERIAL PRIMARY KEY,
  org_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE dns_records (
  id SERIAL PRIMARY KEY,
  deployment_id INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
  type VARCHAR(10) NOT NULL,
  name VARCHAR(255) NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER DEFAULT 300,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE theme_configs (
  id SERIAL PRIMARY KEY,
  deployment_id INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
  primary_color VARCHAR(7),
  secondary_color VARCHAR(7),
  font_family VARCHAR(100),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE deployment_logs (
  id SERIAL PRIMARY KEY,
  deployment_id INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
  level VARCHAR(20) NOT NULL,
  message TEXT NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
`;

function auditLog(entry) {
  db.auditLog.push({
    ...entry,
    timestamp: new Date().toISOString()
  });
}

function logPermissionCheck(req, requiredTier, userTier, decision) {
  auditLog({
    action: 'permission_check',
    userId: req.user?.id,
    // The path only: a query string can carry tokens, and audit readers should not see them (from review).
    endpoint: req.path || String(req.originalUrl || req.url || '').split('?')[0] || 'unknown',
    required_tier: requiredTier,
    user_tier: userTier,
    decision
  });
}

function require_authenticated(req, res, next) {
  if (!req.user) {
    logPermissionCheck(req, 'authenticated', undefined, 'FAIL');
    return res.status(401).json({ error: 'authentication_required', message: 'Authentication required', code: 401 });
  }
  logPermissionCheck(req, 'authenticated', req.user.tier, 'PASS');
  next();
}

function require_admin(req, res, next) {
  if (!req.user) {
    logPermissionCheck(req, ['admin', 'owner'], undefined, 'FAIL');
    return res.status(401).json({ error: 'authentication_required', message: 'Authentication required', code: 401 });
  }
  if (!['admin', 'owner'].includes(req.user.tier)) {
    logPermissionCheck(req, ['admin', 'owner'], req.user.tier, 'FAIL');
    return res.status(403).json({ error: 'admin_only', message: 'Admin only', code: 403 });
  }
  logPermissionCheck(req, ['admin', 'owner'], req.user.tier, 'PASS');
  next();
}

function require_owner(req, res, next) {
  if (!req.user) {
    logPermissionCheck(req, 'owner', undefined, 'FAIL');
    return res.status(401).json({ error: 'authentication_required', message: 'Authentication required', code: 401 });
  }
  if (req.user.tier !== 'owner') {
    logPermissionCheck(req, 'owner', req.user.tier, 'FAIL');
    return res.status(403).json({ error: 'owner_only', message: 'Owner only', code: 403 });
  }
  logPermissionCheck(req, 'owner', req.user.tier, 'PASS');
  next();
}

function deleteUser(userId) {
  const userToDelete = db.users.find(u => u.id === userId);
  const sessionsToDelete = db.sessions.filter(s => s.userId === userId);
  const apiKeysToDelete = db.apiKeys.filter(k => k.userId === userId);
  const filesToDelete = db.files.filter(f => f.userId === userId);
  const preferenceToDelete = db.preferences.find(p => p.userId === userId);

  let deletedUser = null;
  let deletedSessions = [];
  let deletedApiKeys = [];
  let deletedFiles = [];
  let deletedPreference = null;

  try {
    sessionsToDelete.forEach(session => {
      const index = db.sessions.indexOf(session);
      if (index !== -1) {
        db.sessions.splice(index, 1);
        deletedSessions.push(session);
      }
    });

    apiKeysToDelete.forEach(key => {
      const index = db.apiKeys.indexOf(key);
      if (index !== -1) {
        db.apiKeys.splice(index, 1);
        deletedApiKeys.push(key);
      }
    });

    filesToDelete.forEach(file => {
      const index = db.files.indexOf(file);
      if (index !== -1) {
        db.files.splice(index, 1);
        deletedFiles.push(file);
      }
    });

    if (preferenceToDelete) {
      const index = db.preferences.indexOf(preferenceToDelete);
      if (index !== -1) {
        db.preferences.splice(index, 1);
        deletedPreference = preferenceToDelete;
      }
    }

    if (userToDelete) {
      const index = db.users.indexOf(userToDelete);
      if (index !== -1) {
        db.users.splice(index, 1);
        deletedUser = userToDelete;
      }
    }

    const deletedItems = {
      sessions: deletedSessions.length,
      apiKeys: deletedApiKeys.length,
      files: deletedFiles.length,
      preferences: deletedPreference ? 1 : 0,
      users: deletedUser ? 1 : 0
    };

    auditLog({
      action: 'user_deleted_cascade',
      userId,
      deletedItems
    });

    return { success: true, deletedItems };
  } catch (error) {
    if (deletedUser) {
      db.users.push(deletedUser);
    }
    if (deletedPreference) {
      db.preferences.push(deletedPreference);
    }
    deletedFiles.forEach(file => db.files.push(file));
    deletedApiKeys.forEach(key => db.apiKeys.push(key));
    deletedSessions.forEach(session => db.sessions.push(session));
    throw error;
  }
}

function deleteDeployment(deploymentId) {
  const dnsRecordsToDelete = db.dnsRecords.filter(r => r.deploymentId === deploymentId);
  const themeConfigsToDelete = db.themeConfigs.filter(c => c.deploymentId === deploymentId);
  const deploymentLogsToDelete = db.deploymentLogs.filter(l => l.deploymentId === deploymentId);
  const deploymentToDelete = db.deployments.find(d => d.id === deploymentId);

  let deletedDnsRecords = [];
  let deletedThemeConfigs = [];
  let deletedDeploymentLogs = [];
  let deletedDeployment = null;

  try {
    dnsRecordsToDelete.forEach(record => {
      const index = db.dnsRecords.indexOf(record);
      if (index !== -1) {
        db.dnsRecords.splice(index, 1);
        deletedDnsRecords.push(record);
      }
    });

    themeConfigsToDelete.forEach(config => {
      const index = db.themeConfigs.indexOf(config);
      if (index !== -1) {
        db.themeConfigs.splice(index, 1);
        deletedThemeConfigs.push(config);
      }
    });

    deploymentLogsToDelete.forEach(log => {
      const index = db.deploymentLogs.indexOf(log);
      if (index !== -1) {
        db.deploymentLogs.splice(index, 1);
        deletedDeploymentLogs.push(log);
      }
    });

    if (deploymentToDelete) {
      const index = db.deployments.indexOf(deploymentToDelete);
      if (index !== -1) {
        db.deployments.splice(index, 1);
        deletedDeployment = deploymentToDelete;
      }
    }

    const deletedItems = {
      dns: deletedDnsRecords.length,
      themeConfigs: deletedThemeConfigs.length,
      deploymentLogs: deletedDeploymentLogs.length,
      deployment: deletedDeployment ? 1 : 0
    };

    auditLog({
      action: 'deployment_deleted_cascade',
      deploymentId,
      deletedItems
    });

    return { success: true, deletedItems };
  } catch (error) {
    if (deletedDeployment) {
      db.deployments.push(deletedDeployment);
    }
    deletedDeploymentLogs.forEach(log => db.deploymentLogs.push(log));
    deletedThemeConfigs.forEach(config => db.themeConfigs.push(config));
    deletedDnsRecords.forEach(record => db.dnsRecords.push(record));
    throw error;
  }
}

/**
 * Run fn as one transaction over the in-memory tables: every table array is copied first and, if fn throws, every
 * table is put back as it was (no partial deletes, RBAC-07) and the error is rethrown.
 * In: fn() -> result. Out: fn's result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches every in-memory table.
 */
function inTransaction(fn) {
  const snapshot = {};
  for (const name of Object.keys(db)) snapshot[name] = db[name].slice();
  try {
    return fn();
  } catch (error) {
    for (const name of Object.keys(snapshot)) db[name] = snapshot[name];
    throw error;
  }
}

/**
 * deleteOrganization(caller, orgId) -> { success: true, deletedItems } | { success: false, error: 'not_found', code: 404 }.
 * In: caller is the VERIFIED user (req.user from the auth layer, never a request field) and the org id.
 * Gate: the caller must have a membership row (orgId, caller.id) with role 'owner'; anyone else, including a global
 * owner/admin tier, an owner of another org, or no caller, gets 404 so the org's existence is not revealed.
 * Deletes in one transaction: the org's deployments with their dns records, theme configs and logs; API keys whose
 * orgId is this org; all its invitations and membership rows; then the org; logs 'org_deleted_cascade' with
 * {deployments, api_keys, invitations, memberships}. Never deletes a user account, a session, a personal API key
 * (no orgId) or another org's membership. A failure rolls everything back and is rethrown.
 * Why: RBAC-06 amended 2026-11-10 after review on PR 19 (the old cascade deleted every member's user account and all
 * their keys, and anyone could call it). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: organizations, deployments and their child tables, apiKeys, invitations, memberships, auditLog.
 */
function deleteOrganization(caller, orgId) {
  const callerId = caller && caller.id !== undefined && caller.id !== null ? caller.id : null;
  const isOwner = callerId !== null &&
    db.memberships.some(m => m.orgId === orgId && m.userId === callerId && m.role === 'owner');
  if (!isOwner) {
    return { success: false, error: 'not_found', message: 'Organization not found', code: 404 };
  }
  return inTransaction(() => {
    const depIds = new Set(db.deployments.filter(d => d.orgId === orgId).map(d => d.id));
    const counts = {
      deployments: depIds.size,
      api_keys: db.apiKeys.filter(k => k.orgId === orgId).length,
      invitations: db.invitations.filter(i => i.orgId === orgId).length,
      memberships: db.memberships.filter(m => m.orgId === orgId).length
    };
    db.dnsRecords = db.dnsRecords.filter(r => !depIds.has(r.deploymentId));
    db.themeConfigs = db.themeConfigs.filter(c => !depIds.has(c.deploymentId));
    db.deploymentLogs = db.deploymentLogs.filter(l => !depIds.has(l.deploymentId));
    db.deployments = db.deployments.filter(d => !depIds.has(d.id));
    db.apiKeys = db.apiKeys.filter(k => k.orgId !== orgId);
    db.invitations = db.invitations.filter(i => i.orgId !== orgId);
    db.memberships = db.memberships.filter(m => m.orgId !== orgId);
    db.organizations = db.organizations.filter(o => o.id !== orgId);
    auditLog({
      action: 'org_deleted_cascade',
      orgId,
      userId: callerId,
      deletedItems: counts
    });
    return { success: true, deletedItems: counts };
  });
}

function getUserById(id) {
  return db.users.find(u => u.id === id);
}

function getApiKeyById(id) {
  return db.apiKeys.find(k => k.id === id);
}

function getSessionById(id) {
  return db.sessions.find(s => s.id === id);
}

module.exports = {
  db,
  require_owner,
  require_admin,
  require_authenticated,
  deleteUser,
  deleteDeployment,
  deleteOrganization,
  auditLog,
  getAuditLog: () => db.auditLog,
  getUserById,
  getApiKeyById,
  getSessionById,
  ddl,
  resetDb: () => {
    db.users = [];
    db.sessions = [];
    db.apiKeys = [];
    db.files = [];
    db.preferences = [];
    db.deployments = [];
    db.dnsRecords = [];
    db.themeConfigs = [];
    db.deploymentLogs = [];
    db.organizations = [];
    db.memberships = [];
    db.invitations = [];
    db.auditLog = [];
  }
};
