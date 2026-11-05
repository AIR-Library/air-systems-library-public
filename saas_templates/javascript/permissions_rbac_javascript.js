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
    endpoint: req.path || req.url || req.originalUrl || 'unknown',
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

function deleteOrganization(orgId) {
  const deploymentsToDelete = db.deployments.filter(d => d.orgId === orgId);
  const usersToDelete = db.users.filter(u => u.organizationId === orgId);
  const apiKeysToDelete = db.apiKeys.filter(k => {
    return db.users.some(u => u.id === k.userId && u.organizationId === orgId);
  });

  let deletedDeployments = [];
  let deletedUsers = [];
  let deletedApiKeys = [];

  try {
    deploymentsToDelete.forEach(deployment => {
      const index = db.deployments.indexOf(deployment);
      if (index !== -1) {
        db.deployments.splice(index, 1);
        deletedDeployments.push(deployment);
      }
    });

    usersToDelete.forEach(user => {
      const index = db.users.indexOf(user);
      if (index !== -1) {
        db.users.splice(index, 1);
        deletedUsers.push(user);
      }
    });

    apiKeysToDelete.forEach(key => {
      const index = db.apiKeys.indexOf(key);
      if (index !== -1) {
        db.apiKeys.splice(index, 1);
        deletedApiKeys.push(key);
      }
    });

    const orgToDelete = db.organizations.find(o => o.id === orgId);
    let deletedOrganization = null;
    if (orgToDelete) {
      const index = db.organizations.indexOf(orgToDelete);
      if (index !== -1) {
        db.organizations.splice(index, 1);
        deletedOrganization = orgToDelete;
      }
    }

    const deletedItems = {
      deployments: deletedDeployments.length,
      users: deletedUsers.length,
      apiKeys: deletedApiKeys.length,
      organization: deletedOrganization ? 1 : 0
    };

    auditLog({
      action: 'org_deleted_cascade',
      orgId,
      deletedItems
    });

    return { success: true, deletedItems };
  } catch (error) {
    if (deletedOrganization) {
      db.organizations.push(deletedOrganization);
    }
    deletedApiKeys.forEach(key => db.apiKeys.push(key));
    deletedUsers.forEach(user => db.users.push(user));
    deletedDeployments.forEach(deployment => db.deployments.push(deployment));
    throw error;
  }
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
    db.auditLog = [];
  }
};
