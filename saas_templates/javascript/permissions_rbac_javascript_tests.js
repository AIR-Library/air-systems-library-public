const rbac = require('./permissions_rbac_javascript');

describe('Permissions & RBAC System', () => {
  const mockResponse = () => {
    const res = {};
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    return res;
  };

  beforeEach(() => {
    rbac.resetDb();
  });

  describe('Middleware Functions', () => {
    describe('require_authenticated', () => {
      test('should return 401 when no user', () => {
        const req = {};
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_authenticated(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          error: 'authentication_required',
          message: 'Authentication required',
          code: 401
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should call next when user exists', () => {
        const req = { user: { id: 1, tier: 'member' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_authenticated(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });
    });

    describe('require_admin', () => {
      test('should return 401 when no user', () => {
        const req = {};
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_admin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          error: 'authentication_required',
          message: 'Authentication required',
          code: 401
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should return 403 for member tier', () => {
        const req = { user: { id: 1, tier: 'member' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_admin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
          error: 'admin_only',
          message: 'Admin only',
          code: 403
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should return 403 for public tier', () => {
        const req = { user: { id: 1, tier: 'public' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_admin(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
          error: 'admin_only',
          message: 'Admin only',
          code: 403
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should call next for admin tier', () => {
        const req = { user: { id: 1, tier: 'admin' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_admin(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });

      test('should call next for owner tier', () => {
        const req = { user: { id: 1, tier: 'owner' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_admin(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });
    });

    describe('require_owner', () => {
      test('should return 401 when no user', () => {
        const req = {};
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_owner(req, res, next);
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({
          error: 'authentication_required',
          message: 'Authentication required',
          code: 401
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should return 403 for admin tier', () => {
        const req = { user: { id: 1, tier: 'admin' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_owner(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
          error: 'owner_only',
          message: 'Owner only',
          code: 403
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should return 403 for member tier', () => {
        const req = { user: { id: 1, tier: 'member' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_owner(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
          error: 'owner_only',
          message: 'Owner only',
          code: 403
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should return 403 for public tier', () => {
        const req = { user: { id: 1, tier: 'public' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_owner(req, res, next);
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
          error: 'owner_only',
          message: 'Owner only',
          code: 403
        });
        expect(next).not.toHaveBeenCalled();
      });

      test('should call next for owner tier', () => {
        const req = { user: { id: 1, tier: 'owner' } };
        const res = mockResponse();
        const next = jest.fn();
        rbac.require_owner(req, res, next);
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
      });
    });

    describe('Performance', () => {
      test('require_authenticated response time < 10ms', () => {
        const req = { user: { id: 1, tier: 'member' } };
        const res = mockResponse();
        const next = jest.fn();
        const start = Date.now();
        rbac.require_authenticated(req, res, next);
        const end = Date.now();
        expect(end - start).toBeLessThan(10);
      });

      test('require_admin response time < 10ms', () => {
        const req = { user: { id: 1, tier: 'admin' } };
        const res = mockResponse();
        const next = jest.fn();
        const start = Date.now();
        rbac.require_admin(req, res, next);
        const end = Date.now();
        expect(end - start).toBeLessThan(10);
      });

      test('require_owner response time < 10ms', () => {
        const req = { user: { id: 1, tier: 'owner' } };
        const res = mockResponse();
        const next = jest.fn();
        const start = Date.now();
        rbac.require_owner(req, res, next);
        const end = Date.now();
        expect(end - start).toBeLessThan(10);
      });
    });
  });

  describe('Cascade Delete Functions', () => {
    describe('deleteUser', () => {
      test('should delete user and all related records', () => {
        const user = { id: 1, tier: 'member' };
        rbac.db.users.push(user);
        rbac.db.sessions.push({ id: 1, userId: 1, token: 's1', expires_at: new Date() });
        rbac.db.sessions.push({ id: 2, userId: 1, token: 's2', expires_at: new Date() });
        rbac.db.apiKeys.push({ id: 1, userId: 1, key: 'k1', name: 'key1' });
        rbac.db.files.push({ id: 1, userId: 1, filename: 'file1.txt', size: 100 });
        rbac.db.preferences.push({ id: 1, userId: 1, theme: 'dark' });

        const result = rbac.deleteUser(1);
        expect(result.success).toBe(true);
        expect(result.deletedItems).toEqual({
          sessions: 2,
          apiKeys: 1,
          files: 1,
          preferences: 1,
          users: 1
        });
        expect(rbac.db.users.length).toBe(0);
        expect(rbac.db.sessions.length).toBe(0);
        expect(rbac.db.apiKeys.length).toBe(0);
        expect(rbac.db.files.length).toBe(0);
        expect(rbac.db.preferences.length).toBe(0);
        expect(rbac.getAuditLog().length).toBe(1);
        expect(rbac.getAuditLog()[0]).toMatchObject({
          action: 'user_deleted_cascade',
          userId: 1,
          deletedItems: {
            sessions: 2,
            apiKeys: 1,
            files: 1,
            preferences: 1,
            users: 1
          }
        });
      });

      test('should rollback on error during deletion', () => {
        const user = { id: 1, tier: 'member' };
        rbac.db.users.push(user);
        rbac.db.sessions.push({ id: 1, userId: 1, token: 's1', expires_at: new Date() });
        rbac.db.apiKeys.push({ id: 1, userId: 1, key: 'k1', name: 'key1' });
        
        // Mock array.splice to throw error on second call
        const originalSplice = Array.prototype.splice;
        let callCount = 0;
        Array.prototype.splice = function() {
          callCount++;
          if (callCount === 2) {
            throw new Error('Simulated error');
          }
          return originalSplice.apply(this, arguments);
        };

        try {
          rbac.deleteUser(1);
          fail('Expected error to be thrown');
        } catch (e) {
          // Expect rollback
          expect(rbac.db.users.length).toBe(1);
          expect(rbac.db.sessions.length).toBe(1);
          expect(rbac.db.apiKeys.length).toBe(1);
          expect(rbac.getAuditLog().length).toBe(0);
        } finally {
          Array.prototype.splice = originalSplice;
        }
      });
    });

    describe('deleteDeployment', () => {
      test('should delete deployment and all related records', () => {
        const org = { id: 1, name: 'Org1' };
        rbac.db.organizations.push(org);
        const deployment = { id: 1, orgId: 1, name: 'Dep1', status: 'active' };
        rbac.db.deployments.push(deployment);
        rbac.db.dnsRecords.push({ id: 1, deploymentId: 1, type: 'A', name: 'example.com', value: '1.2.3.4' });
        rbac.db.dnsRecords.push({ id: 2, deploymentId: 1, type: 'CNAME', name: 'www.example.com', value: 'example.com' });
        rbac.db.themeConfigs.push({ id: 1, deploymentId: 1, primary_color: '#fff', secondary_color: '#000', font_family: 'Arial' });
        rbac.db.deploymentLogs.push({ id: 1, deploymentId: 1, level: 'info', message: 'Deployed' });
        rbac.db.deploymentLogs.push({ id: 2, deploymentId: 1, level: 'error', message: 'Failed' });

        const result = rbac.deleteDeployment(1);
        expect(result.success).toBe(true);
        expect(result.deletedItems).toEqual({
          dns: 2,
          themeConfigs: 1,
          deploymentLogs: 2,
          deployment: 1
        });
        expect(rbac.db.deployments.length).toBe(0);
        expect(rbac.db.dnsRecords.length).toBe(0);
        expect(rbac.db.themeConfigs.length).toBe(0);
        expect(rbac.db.deploymentLogs.length).toBe(0);
        expect(rbac.getAuditLog().length).toBe(1);
        expect(rbac.getAuditLog()[0]).toMatchObject({
          action: 'deployment_deleted_cascade',
          deploymentId: 1,
          deletedItems: {
            dns: 2,
            themeConfigs: 1,
            deploymentLogs: 2,
            deployment: 1
          }
        });
      });
    });

    describe('deleteOrganization', () => {
      test('should delete organization and all nested records', () => {
        const org = { id: 1, name: 'Org1' };
        rbac.db.organizations.push(org);
        const user = { id: 1, tier: 'member', organizationId: 1 };
        rbac.db.users.push(user);
        const deployment = { id: 1, orgId: 1, name: 'Dep1', status: 'active' };
        rbac.db.deployments.push(deployment);
        rbac.db.apiKeys.push({ id: 1, userId: 1, key: 'k1', name: 'key1' });

        const result = rbac.deleteOrganization(1);
        expect(result.success).toBe(true);
        expect(result.deletedItems).toEqual({
          deployments: 1,
          users: 1,
          apiKeys: 1,
          organization: 1
        });
        expect(rbac.db.organizations.length).toBe(0);
        expect(rbac.db.users.length).toBe(0);
        expect(rbac.db.deployments.length).toBe(0);
        expect(rbac.db.apiKeys.length).toBe(0);
        expect(rbac.getAuditLog().length).toBe(1);
        expect(rbac.getAuditLog()[0]).toMatchObject({
          action: 'org_deleted_cascade',
          orgId: 1,
          deletedItems: {
            deployments: 1,
            users: 1,
            apiKeys: 1,
            organization: 1
          }
        });
      });
    });
  });

  describe('Permission Audit Logging', () => {
    test('should log permission check for failed authentication', () => {
      const req = {};
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_authenticated(req, res, next);
      const logs = rbac.getAuditLog();
      expect(logs.length).toBe(1);
      expect(logs[0]).toMatchObject({
        action: 'permission_check',
        userId: undefined,
        endpoint: expect.any(String),
        required_tier: 'authenticated',
        user_tier: undefined,
        decision: 'FAIL'
      });
    });

    test('should log permission check for failed admin access', () => {
      const req = { user: { id: 1, tier: 'member' } };
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_admin(req, res, next);
      const logs = rbac.getAuditLog();
      expect(logs.length).toBe(1);
      expect(logs[0]).toMatchObject({
        action: 'permission_check',
        userId: 1,
        endpoint: expect.any(String),
        required_tier: ['admin', 'owner'],
        user_tier: 'member',
        decision: 'FAIL'
      });
    });

    test('should log permission check for passed owner access', () => {
      const req = { user: { id: 1, tier: 'owner' } };
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_owner(req, res, next);
      const logs = rbac.getAuditLog();
      expect(logs.length).toBe(1);
      expect(logs[0]).toMatchObject({
        action: 'permission_check',
        userId: 1,
        endpoint: expect.any(String),
        required_tier: 'owner',
        user_tier: 'owner',
        decision: 'PASS'
      });
    });
  });

  describe('Tier Hierarchy', () => {
    test('member cannot perform admin actions', () => {
      const req = { user: { id: 1, tier: 'member' } };
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_admin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        error: 'admin_only',
        message: 'Admin only',
        code: 403
      });
    });

    test('admin cannot perform owner actions', () => {
      const req = { user: { id: 1, tier: 'admin' } };
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_owner(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        error: 'owner_only',
        message: 'Owner only',
        code: 403
      });
    });

    test('owner can perform admin actions', () => {
      const req = { user: { id: 1, tier: 'owner' } };
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_admin(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    test('admin can perform member actions (implicitly via authentication)', () => {
      const req = { user: { id: 1, tier: 'admin' } };
      const res = mockResponse();
      const next = jest.fn();
      rbac.require_authenticated(req, res, next);
      expect(next).toHaveBeenCalled();
    });
  });
});
