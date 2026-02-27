const request = require('supertest');
const app = require('./app');

// Test configuration
const TEST_ADMIN_ID = '123456789';
const API_BASE_URL = 'http://localhost:3000';

describe('SSH & Server Management API Tests', () => {
  let server;
  
  beforeAll(async () => {
    // Wait for database initialization
    await new Promise(resolve => setTimeout(resolve, 2000));
  });
  
  afterAll(async () => {
    if (server) {
      server.close();
    }
  });

  // Health Check Tests
  describe('Health Check', () => {
    test('GET /health should return healthy status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);
      
      expect(response.body.status).toBe('healthy');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  // Admin Tests
  describe('Admin Management', () => {
    test('POST /admin/add should add first admin without auth', async () => {
      const response = await request(app)
        .post('/admin/add')
        .send({ user_id: TEST_ADMIN_ID })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('added successfully');
    });

    test('POST /admin/add should reject duplicate admin', async () => {
      const response = await request(app)
        .post('/admin/add')
        .send({ user_id: TEST_ADMIN_ID })
        .expect(400);
      
      expect(response.body.error).toContain('already exists');
    });
  });

  // Authentication Tests
  describe('Authentication', () => {
    test('Should reject requests without X-User-ID header', async () => {
      const response = await request(app)
        .get('/ssh/members')
        .expect(401);
      
      expect(response.body.error).toContain('X-User-ID header is required');
    });

    test('Should reject requests with invalid X-User-ID', async () => {
      const response = await request(app)
        .get('/ssh/members')
        .set('X-User-ID', 'invalid-user-id')
        .expect(401);
      
      expect(response.body.error).toContain('Unauthorized access');
    });

    test('Should accept requests with valid X-User-ID', async () => {
      const response = await request(app)
        .get('/ssh/members')
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
    });
  });

  // SSH Management Tests
  describe('SSH Management', () => {
    const testUsername = `test-${Date.now()}`;
    
    test('POST /ssh/create should create SSH account', async () => {
      const response = await request(app)
        .post('/ssh/create')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          username: testUsername,
          password: 'testpass123',
          ip_limit: 2,
          days: 7
        })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.username).toBe(testUsername);
    });

    test('GET /ssh/members should list SSH members', async () => {
      const response = await request(app)
        .get('/ssh/members')
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.total_members).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(response.body.data.members)).toBe(true);
    });

    test('GET /ssh/config/:username should get SSH config', async () => {
      const response = await request(app)
        .get(`/ssh/config/${testUsername}`)
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.username).toBe(testUsername);
    });

    test('PUT /ssh/change-limit should change IP limit', async () => {
      const response = await request(app)
        .put('/ssh/change-limit')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          username: testUsername,
          ip_limit: 3
        })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.new_ip_limit).toBe(3);
    });

    test('PUT /ssh/lock should lock SSH user', async () => {
      const response = await request(app)
        .put('/ssh/lock')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({ username: testUsername })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('locked successfully');
    });

    test('PUT /ssh/unlock should unlock SSH user', async () => {
      const response = await request(app)
        .put('/ssh/unlock')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({ username: testUsername })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('unlocked successfully');
    });

    test('PUT /ssh/renew should renew SSH user', async () => {
      const response = await request(app)
        .put('/ssh/renew')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          username: testUsername,
          days: 14
        })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.extended_days).toBe(14);
    });

    test('DELETE /ssh/delete should delete SSH user', async () => {
      const response = await request(app)
        .delete('/ssh/delete')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({ username: testUsername })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('deleted successfully');
    });

    test('POST /ssh/trial should create trial SSH account', async () => {
      const response = await request(app)
        .post('/ssh/trial')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          ip_limit: 1,
          minutes: 30
        })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.username).toMatch(/^trial-\d+$/);
      
      // Clean up trial user
      await request(app)
        .delete('/ssh/delete')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({ username: response.body.data.username });
    });

    test('GET /ssh/check-login should check login status', async () => {
      const response = await request(app)
        .get('/ssh/check-login')
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.login_info).toBeDefined();
    });
  });

  // Server Management Tests
  describe('Server Management', () => {
    let serverId;
    const testServerName = `test-server-${Date.now()}`;
    
    test('POST /servers should add new server', async () => {
      const response = await request(app)
        .post('/servers')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          name: testServerName,
          ip_address: '127.0.0.1',
          port: 22,
          username: 'testuser'
        })
        .expect(201);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe(testServerName);
      serverId = response.body.data.id;
    });

    test('GET /servers should list all servers', async () => {
      const response = await request(app)
        .get('/servers')
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.total_servers).toBeGreaterThanOrEqual(1);
      expect(Array.isArray(response.body.data.servers)).toBe(true);
    });

    test('PUT /servers/:id should update server', async () => {
      const response = await request(app)
        .put(`/servers/${serverId}`)
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          name: `${testServerName}-updated`,
          status: 'inactive'
        })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.name).toBe(`${testServerName}-updated`);
    });

    test('POST /servers/:id/test should test server connection', async () => {
      const response = await request(app)
        .post(`/servers/${serverId}/test`)
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.connection_status).toBeDefined();
    });

    test('DELETE /servers/:id should delete server', async () => {
      const response = await request(app)
        .delete(`/servers/${serverId}`)
        .set('X-User-ID', TEST_ADMIN_ID)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('deleted successfully');
    });
  });

  // Error Handling Tests
  describe('Error Handling', () => {
    test('Should return 404 for non-existent endpoints', async () => {
      const response = await request(app)
        .get('/non-existent-endpoint')
        .expect(404);
      
      expect(response.body.error).toBe('Endpoint not found');
    });

    test('Should validate required fields', async () => {
      const response = await request(app)
        .post('/ssh/create')
        .set('X-User-ID', TEST_ADMIN_ID)
        .send({
          username: 'testuser'
          // missing password
        })
        .expect(400);
      
      expect(response.body.error).toContain('password are required');
    });
  });
});

// Manual testing functions for development
if (require.main === module) {
  console.log('🧪 Running manual API tests...');
  
  const testEndpoints = async () => {
    const baseURL = 'http://localhost:3000';
    const headers = {
      'Content-Type': 'application/json',
      'X-User-ID': TEST_ADMIN_ID
    };
    
    try {
      // Test health check
      console.log('Testing health check...');
      const healthResponse = await fetch(`${baseURL}/health`);
      const healthData = await healthResponse.json();
      console.log('✅ Health check:', healthData.status);
      
      // Test SSH members
      console.log('Testing SSH members...');
      const membersResponse = await fetch(`${baseURL}/ssh/members`, { headers });
      const membersData = await membersResponse.json();
      console.log('✅ SSH members:', membersData.data?.total_members || 0);
      
      // Test servers list
      console.log('Testing servers list...');
      const serversResponse = await fetch(`${baseURL}/servers`, { headers });
      const serversData = await serversResponse.json();
      console.log('✅ Servers:', serversData.data?.total_servers || 0);
      
      console.log('🎉 Manual tests completed successfully!');
      
    } catch (error) {
      console.error('❌ Manual test failed:', error.message);
    }
  };
  
  // Run manual tests after a delay to allow server startup
  setTimeout(testEndpoints, 3000);
}
