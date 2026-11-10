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
      // RBAC-03
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

      // RBAC-02
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

      // RBAC-01
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

      // RBAC-10
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
      // RBAC-04
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

      // RBAC-07
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
      // RBAC-05
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
      /**
       * Seeds two orgs: org 1 (owner 1, member 2, member 3) and org 2 (owner 9, member 3 as admin), with deployments,
       * org keys, personal keys, sessions and invitations. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
       */
      const seedTwoOrgs = () => {
        rbac.db.organizations.push({ id: 1, name: 'Org1' }, { id: 2, name: 'Org2' });
        rbac.db.users.push({ id: 1, tier: 'owner' }, { id: 2, tier: 'member' }, { id: 3, tier: 'member' }, { id: 9, tier: 'owner' });
        rbac.db.memberships.push(
          { orgId: 1, userId: 1, role: 'owner' },
          { orgId: 1, userId: 2, role: 'member' },
          { orgId: 1, userId: 3, role: 'member' },
          { orgId: 2, userId: 9, role: 'owner' },
          { orgId: 2, userId: 3, role: 'admin' }
        );
        rbac.db.sessions.push({ id: 1, userId: 2, token: 's2', expires_at: new Date(0) });
        rbac.db.deployments.push({ id: 1, orgId: 1, name: 'Dep1', status: 'active' }, { id: 2, orgId: 2, name: 'Dep2', status: 'active' });
        rbac.db.dnsRecords.push({ id: 1, deploymentId: 1, type: 'A', name: 'a.example', value: '1.2.3.4' });
        rbac.db.dnsRecords.push({ id: 2, deploymentId: 2, type: 'A', name: 'b.example', value: '5.6.7.8' });
        rbac.db.apiKeys.push(
          { id: 1, userId: 2, orgId: 1, key: 'org1-key', name: 'org key' },
          { id: 2, userId: 2, key: 'personal-2', name: 'personal' },
          { id: 3, userId: 3, orgId: 2, key: 'org2-key', name: 'org2 key' }
        );
        rbac.db.invitations.push({ id: 1, orgId: 1, email: 'a@x.test' }, { id: 2, orgId: 1, email: 'b@x.test' }, { id: 3, orgId: 2, email: 'c@x.test' });
      };

      // RBAC-06
      // 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: rewritten for the amended spec. The old test expected every
      // member's user account and personal keys to be deleted; the spec now forbids that and gates on an org owner.
      test('owner of the org deletes its deployments, org keys, invitations and memberships; accounts kept', () => {
        seedTwoOrgs();
        const result = rbac.deleteOrganization({ id: 1, tier: 'owner' }, 1);
        expect(result.success).toBe(true);
        expect(result.deletedItems).toEqual({ deployments: 1, api_keys: 1, invitations: 2, memberships: 3 });
        expect(rbac.db.organizations.map(o => o.id)).toEqual([2]);
        expect(rbac.db.deployments.map(d => d.id)).toEqual([2]);
        expect(rbac.db.dnsRecords.map(r => r.id)).toEqual([2]);
        expect(rbac.db.apiKeys.map(k => k.id)).toEqual([2, 3]);
        expect(rbac.db.invitations.map(i => i.id)).toEqual([3]);
        expect(rbac.db.users.map(u => u.id)).toEqual([1, 2, 3, 9]);
        expect(rbac.db.sessions.length).toBe(1);
        expect(rbac.db.memberships).toEqual([
          { orgId: 2, userId: 9, role: 'owner' },
          { orgId: 2, userId: 3, role: 'admin' }
        ]);
        const log = rbac.getAuditLog().filter(e => e.action === 'org_deleted_cascade');
        expect(log.length).toBe(1);
        expect(log[0]).toMatchObject({ orgId: 1, deletedItems: { deployments: 1, api_keys: 1, invitations: 2, memberships: 3 } });
      });

      // RBAC-06
      test('another org\'s owner, a non-owner member, a global owner tier and no caller all get 404, nothing deleted', () => {
        seedTwoOrgs();
        const before = JSON.stringify(rbac.db);
        for (const caller of [{ id: 9, tier: 'owner' }, { id: 2, tier: 'member' }, { id: 3, tier: 'owner' }, null, undefined]) {
          const result = rbac.deleteOrganization(caller, 1);
          expect(result).toMatchObject({ success: false, error: 'not_found', code: 404 });
        }
        expect(JSON.stringify(rbac.db)).toBe(before);
      });

      // RBAC-07
      test('org cascade failure rolls back every table', () => {
        seedTwoOrgs();
        const before = JSON.stringify(rbac.db);
        // The organizations table is the last one the cascade touches, so by then every other table has been changed.
        rbac.db.organizations.filter = () => { throw new Error('Simulated error'); };
        expect(() => rbac.deleteOrganization({ id: 1, tier: 'owner' }, 1)).toThrow('Simulated error');
        expect(rbac.db.deployments.length).toBe(2);
        expect(rbac.db.memberships.length).toBe(5);
        expect(JSON.stringify(rbac.db)).toBe(before);
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

    // RBAC-08
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

    // RBAC-08
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
    // RBAC-09
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

    // RBAC-09
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
