const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './database.db';

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Database initialization
let db;

function initDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
        reject(err);
      } else {
        console.log('✅ Connected to SQLite database');
        
        // Create tables
        db.serialize(() => {
          // Admin table
          db.run(`CREATE TABLE IF NOT EXISTS admin (
            user_id TEXT PRIMARY KEY
          )`);
          
          // Servers table
          db.run(`CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            username TEXT NOT NULL,
            password TEXT,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
          )`);
          
          // SSH users table
          db.run(`CREATE TABLE IF NOT EXISTS ssh_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            ip_limit INTEGER DEFAULT 1,
            expired_date DATE NOT NULL,
            created_date DATE DEFAULT CURRENT_DATE,
            status TEXT DEFAULT 'active'
          )`, (err) => {
            if (err) {
              reject(err);
            } else {
              console.log('✅ Database tables initialized');
              resolve();
            }
          });
        });
      }
    });
  });
}

// Authentication middleware
function requireAuth(req, res, next) {
  const userId = req.headers['x-user-id'];
  
  if (!userId) {
    return res.status(401).json({ error: 'X-User-ID header is required' });
  }
  
  // Check if user is admin
  db.get('SELECT user_id FROM admin WHERE user_id = ?', [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!row) {
      return res.status(401).json({ error: 'Unauthorized access' });
    }
    
    req.userId = userId;
    next();
  });
}

// Utility function to execute shell commands
function executeCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject({ error: error.message, stderr });
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// ==================== ADMIN ENDPOINTS ====================

app.post('/admin/add', (req, res) => {
  const { user_id } = req.body;
  
  if (!user_id) {
    return res.status(400).json({ error: 'User ID is required' });
  }
  
  // Check if this is initial setup (no admins exist)
  db.get('SELECT COUNT(*) as count FROM admin', (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    // If admins exist, require authentication
    if (row.count > 0) {
      const authUserId = req.headers['x-user-id'];
      if (!authUserId) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      
      db.get('SELECT user_id FROM admin WHERE user_id = ?', [authUserId], (err, adminRow) => {
        if (err || !adminRow) {
          return res.status(401).json({ error: 'Unauthorized access' });
        }
        
        addAdmin();
      });
    } else {
      addAdmin();
    }
    
    function addAdmin() {
      db.run('INSERT INTO admin (user_id) VALUES (?)', [user_id], function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Admin already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({
          success: true,
          message: `Admin ${user_id} added successfully`
        });
      });
    }
  });
});

// ==================== SSH ENDPOINTS ====================

// Create SSH Account
app.post('/ssh/create', requireAuth, async (req, res) => {
  try {
    const { username, password, ip_limit = 1, days = 30 } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Calculate expiry date
    const expDate = new Date();
    expDate.setDate(expDate.getDate() + parseInt(days));
    const expDateStr = expDate.toISOString().split('T')[0];
    
    // Create system user using shell command
    const command = `printf "${username}\\n${password}\\n${ip_limit}\\n${days}\\n" | /usr/local/bin/add-ssh add`;
    
    try {
      await executeCommand(command);
      
      // Save to database
      db.run(
        'INSERT INTO ssh_users (username, password, ip_limit, expired_date) VALUES (?, ?, ?, ?)',
        [username, password, ip_limit, expDateStr],
        function(err) {
          if (err) {
            console.error('Database error:', err);
          }
        }
      );
      
      res.json({
        success: true,
        message: 'SSH account created successfully',
        data: {
          username,
          password,
          ip_limit,
          expired_date: expDateStr,
          domain: process.env.DOMAIN || 'your-domain.com',
          ports: {
            ssh: '22, 2222',
            dropbear: '143, 109',
            ws: '80',
            ssl_ws: '443',
            ovpn_tcp: '1194',
            ovpn_udp: '2200'
          }
        }
      });
      
    } catch (cmdError) {
      res.status(500).json({
        error: 'Failed to create SSH user',
        details: cmdError.error || cmdError.stderr
      });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Trial SSH Account
app.post('/ssh/trial', requireAuth, async (req, res) => {
  try {
    const { ip_limit = 1, minutes = 60 } = req.body;
    
    // Generate random username
    const username = `trial-${Math.floor(Math.random() * 9000) + 1000}`;
    const password = '1';
    
    // Create system user
    const command = `printf "${username}\\n${password}\\n${ip_limit}\\n${minutes}\\n" | /usr/local/bin/add-ssh trial`;
    
    try {
      await executeCommand(command);
      
      // Calculate expiry time
      const expTime = new Date();
      expTime.setMinutes(expTime.getMinutes() + parseInt(minutes));
      
      res.json({
        success: true,
        message: 'Trial SSH account created successfully',
        data: {
          username,
          password,
          ip_limit,
          expired_time: expTime.toISOString(),
          duration_minutes: minutes,
          domain: process.env.DOMAIN || 'your-domain.com'
        }
      });
      
    } catch (cmdError) {
      res.status(500).json({
        error: 'Failed to create trial SSH user',
        details: cmdError.error || cmdError.stderr
      });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete SSH Account
app.delete('/ssh/delete', requireAuth, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Delete system user
    const command = `printf "${username}\\n" | /usr/local/bin/sbot delete ssh`;
    
    try {
      await executeCommand(command);
      
      // Remove from database
      db.run('DELETE FROM ssh_users WHERE username = ?', [username], function(err) {
        if (err) {
          console.error('Database error:', err);
        }
      });
      
      res.json({
        success: true,
        message: `SSH user ${username} deleted successfully`
      });
      
    } catch (cmdError) {
      res.status(404).json({ error: `User ${username} not found` });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Renew SSH Account
app.put('/ssh/renew', requireAuth, async (req, res) => {
  try {
    const { username, days = 30 } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Renew system user
    const command = `printf "${username}\\n${days}\\n" | /usr/local/bin/sbot renew ssh`;
    
    try {
      await executeCommand(command);
      
      // Update database
      const newExpDate = new Date();
      newExpDate.setDate(newExpDate.getDate() + parseInt(days));
      const newExpDateStr = newExpDate.toISOString().split('T')[0];
      
      db.run(
        'UPDATE ssh_users SET expired_date = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?',
        [newExpDateStr, username],
        function(err) {
          if (err) {
            console.error('Database error:', err);
          }
        }
      );
      
      res.json({
        success: true,
        message: `SSH user ${username} renewed successfully`,
        data: {
          username,
          new_expired_date: newExpDateStr,
          extended_days: days
        }
      });
      
    } catch (cmdError) {
      res.status(404).json({ error: `User ${username} not found` });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Check SSH Login Status
app.get('/ssh/check-login', requireAuth, async (req, res) => {
  try {
    const command = '/usr/local/bin/cek-login ssh bot';
    
    try {
      const result = await executeCommand(command);
      
      res.json({
        success: true,
        message: 'SSH login status retrieved',
        data: {
          login_info: result.stdout,
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (cmdError) {
      res.status(500).json({
        error: 'Failed to check login status',
        details: cmdError.error || cmdError.stderr
      });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get SSH User Configuration
app.get('/ssh/config/:username', requireAuth, async (req, res) => {
  try {
    const { username } = req.params;
    
    const command = `printf "${username}\\n" | /usr/local/bin/sbot cfssh`;
    
    try {
      const result = await executeCommand(command);
      
      // Parse config info
      const infoMatch = result.stdout.match(/info:\/\/(.+)/);
      if (infoMatch) {
        const info = infoMatch[1];
        const ipLimitMatch = info.match(/@(.+?):/);
        const passwordMatch = info.match(/#(.+?):/);
        const expDateMatch = info.match(/&(.+?):/);
        
        res.json({
          success: true,
          message: 'SSH configuration retrieved',
          data: {
            username,
            password: passwordMatch ? passwordMatch[1] : null,
            ip_limit: ipLimitMatch ? ipLimitMatch[1] : null,
            expired_date: expDateMatch ? expDateMatch[1] : null,
            domain: process.env.DOMAIN || 'your-domain.com',
            host_slowdns: process.env.HOST || 'your-host.com',
            pub_key: process.env.PUB || 'your-pub-key'
          }
        });
      } else {
        res.status(500).json({ error: 'Failed to parse configuration' });
      }
      
    } catch (cmdError) {
      res.status(404).json({ error: `User ${username} not found` });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Change SSH IP Limit
app.put('/ssh/change-limit', requireAuth, async (req, res) => {
  try {
    const { username, ip_limit } = req.body;
    
    if (!username || ip_limit === undefined) {
      return res.status(400).json({ error: 'Username and ip_limit are required' });
    }
    
    // Change IP limit
    const command = `printf "${username}\\n${ip_limit}\\n" | /usr/local/bin/sbot ipssh`;
    
    try {
      await executeCommand(command);
      
      // Update database
      db.run(
        'UPDATE ssh_users SET ip_limit = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?',
        [ip_limit, username],
        function(err) {
          if (err) {
            console.error('Database error:', err);
          }
        }
      );
      
      res.json({
        success: true,
        message: `IP limit changed successfully for ${username}`,
        data: {
          username,
          new_ip_limit: ip_limit
        }
      });
      
    } catch (cmdError) {
      res.status(404).json({ error: `User ${username} not found` });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Lock SSH User
app.put('/ssh/lock', requireAuth, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Lock user
    const command = `egrep "${username}" /etc/passwd && passwd -l "${username}" && systemctl restart ws`;
    
    try {
      await executeCommand(command);
      
      // Update database
      db.run(
        'UPDATE ssh_users SET status = "locked", updated_at = CURRENT_TIMESTAMP WHERE username = ?',
        [username],
        function(err) {
          if (err) {
            console.error('Database error:', err);
          }
        }
      );
      
      res.json({
        success: true,
        message: `SSH user ${username} locked successfully`
      });
      
    } catch (cmdError) {
      res.status(404).json({ error: `User ${username} not found` });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Unlock SSH User
app.put('/ssh/unlock', requireAuth, async (req, res) => {
  try {
    const { username } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Unlock user
    const command = `egrep "${username}" /etc/passwd && passwd -u "${username}" && systemctl restart ws`;
    
    try {
      await executeCommand(command);
      
      // Update database
      db.run(
        'UPDATE ssh_users SET status = "active", updated_at = CURRENT_TIMESTAMP WHERE username = ?',
        [username],
        function(err) {
          if (err) {
            console.error('Database error:', err);
          }
        }
      );
      
      res.json({
        success: true,
        message: `SSH user ${username} unlocked successfully`
      });
      
    } catch (cmdError) {
      res.status(404).json({ error: `User ${username} not found` });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List SSH Members
app.get('/ssh/members', requireAuth, async (req, res) => {
  try {
    const command = '/usr/local/bin/sbot member ssh';
    
    try {
      const result = await executeCommand(command);
      
      // Parse member list
      const members = [];
      const lines = result.stdout.trim().split('\n');
      
      for (let i = 3; i < lines.length; i++) { // Skip header lines
        const line = lines[i].trim();
        if (line) {
          const parts = line.split(/\s+/);
          if (parts.length >= 3) {
            members.push({
              username: parts[0],
              expired_date: parts[1],
              status: parts[2] || 'UNKNOWN'
            });
          }
        }
      }
      
      res.json({
        success: true,
        message: 'SSH members retrieved successfully',
        data: {
          total_members: members.length,
          members
        }
      });
      
    } catch (cmdError) {
      res.status(500).json({
        error: 'Failed to retrieve SSH members',
        details: cmdError.error || cmdError.stderr
      });
    }
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== SERVER MANAGEMENT ENDPOINTS ====================

// List All Servers
app.get('/servers', requireAuth, (req, res) => {
  db.all(
    'SELECT id, name, ip_address, port, username, status, created_at, updated_at FROM servers ORDER BY created_at DESC',
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({
        success: true,
        message: 'Servers retrieved successfully',
        data: {
          total_servers: rows.length,
          servers: rows
        }
      });
    }
  );
});

// Add New Server
app.post('/servers', requireAuth, async (req, res) => {
  try {
    const { name, ip_address, port = 22, username, password } = req.body;
    
    if (!name || !ip_address || !username) {
      return res.status(400).json({ error: 'Name, IP address, and username are required' });
    }
    
    // Test connection to server
    const testCommand = `timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${username}@${ip_address} -p ${port} "echo Connection successful"`;
    
    let status = 'inactive';
    try {
      await executeCommand(testCommand);
      status = 'active';
    } catch (testError) {
      // Connection failed, but we'll still add the server
    }
    
    // Add to database
    db.run(
      'INSERT INTO servers (name, ip_address, port, username, password, status) VALUES (?, ?, ?, ?, ?, ?)',
      [name, ip_address, port, username, password, status],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        
        res.status(201).json({
          success: true,
          message: 'Server added successfully',
          data: {
            id: this.lastID,
            name,
            ip_address,
            port,
            username,
            status,
            connection_test: status === 'active' ? 'passed' : 'failed'
          }
        });
      }
    );
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Server
app.put('/servers/:id', requireAuth, (req, res) => {
  const serverId = req.params.id;
  const { name, ip_address, port, username, password, status } = req.body;
  
  // Get current server data
  db.get('SELECT * FROM servers WHERE id = ?', [serverId], (err, server) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    // Update fields
    const updatedName = name || server.name;
    const updatedIpAddress = ip_address || server.ip_address;
    const updatedPort = port || server.port;
    const updatedUsername = username || server.username;
    const updatedPassword = password || server.password;
    const updatedStatus = status || server.status;
    
    // Update database
    db.run(
      'UPDATE servers SET name = ?, ip_address = ?, port = ?, username = ?, password = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [updatedName, updatedIpAddress, updatedPort, updatedUsername, updatedPassword, updatedStatus, serverId],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        
        res.json({
          success: true,
          message: 'Server updated successfully',
          data: {
            id: parseInt(serverId),
            name: updatedName,
            ip_address: updatedIpAddress,
            port: updatedPort,
            username: updatedUsername,
            status: updatedStatus
          }
        });
      }
    );
  });
});

// Delete Server
app.delete('/servers/:id', requireAuth, (req, res) => {
  const serverId = req.params.id;
  
  // Check if server exists
  db.get('SELECT name FROM servers WHERE id = ?', [serverId], (err, server) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    // Delete server
    db.run('DELETE FROM servers WHERE id = ?', [serverId], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json({
        success: true,
        message: `Server ${server.name} deleted successfully`
      });
    });
  });
});

// Test Server Connection
app.post('/servers/:id/test', requireAuth, async (req, res) => {
  const serverId = req.params.id;
  
  try {
    // Get server data
    const server = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM servers WHERE id = ?', [serverId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    // Record start time for response time calculation
    const startTime = Date.now();
    
    let connectionStatus = 'failed';
    let errorMessage = null;
    let responseTime = 'N/A';
    let connectionDetails = {};
    
    try {
      // Test different connection methods based on server configuration
      let testCommand;
      
      // Try SSH connection first
      if (server.password) {
        // Use sshpass if password is provided (requires sshpass to be installed)
        testCommand = `timeout 10 sshpass -p '${server.password}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${server.username}@${server.ip_address} -p ${server.port} "echo 'SSH Connection successful'"`;
      } else {
        // Use key-based authentication
        testCommand = `timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no ${server.username}@${server.ip_address} -p ${server.port} "echo 'SSH Connection successful'"`;
      }
      
      const result = await executeCommand(testCommand);
      
      if (result.stdout.includes('SSH Connection successful')) {
        connectionStatus = 'success';
        responseTime = `${Date.now() - startTime}ms`;
        connectionDetails = {
          ssh_accessible: true,
          authentication: server.password ? 'password' : 'key-based',
          test_method: 'SSH command execution'
        };
      } else {
        connectionStatus = 'failed';
        errorMessage = 'SSH command executed but no success message received';
      }
      
    } catch (sshError) {
      // If SSH fails, try basic network connectivity tests
      try {
        // Test ping first
        const pingCommand = `timeout 5 ping -c 1 ${server.ip_address}`;
        await executeCommand(pingCommand);
        
        // Ping successful, try to check if port is open
        try {
          const portCommand = `timeout 5 nc -z ${server.ip_address} ${server.port}`;
          await executeCommand(portCommand);
          
          connectionStatus = 'partial'; // Network reachable, port open, but SSH failed
          errorMessage = `Network and port accessible, but SSH authentication failed: ${sshError.error || sshError.stderr}`;
          responseTime = `${Date.now() - startTime}ms`;
          connectionDetails = {
            network_accessible: true,
            port_open: true,
            ssh_accessible: false,
            test_method: 'Network connectivity + Port check'
          };
          
        } catch (portError) {
          connectionStatus = 'failed';
          errorMessage = `Network reachable but port ${server.port} is closed or filtered`;
          responseTime = `${Date.now() - startTime}ms`;
          connectionDetails = {
            network_accessible: true,
            port_open: false,
            ssh_accessible: false,
            test_method: 'Network connectivity test'
          };
        }
        
      } catch (pingError) {
        connectionStatus = 'failed';
        errorMessage = `Network unreachable: ${server.ip_address} is not responding to ping`;
        responseTime = `${Date.now() - startTime}ms`;
        connectionDetails = {
          network_accessible: false,
          port_open: false,
          ssh_accessible: false,
          test_method: 'Full connectivity test'
        };
      }
    }
    
    // Determine new server status based on connection test
    let newStatus;
    switch (connectionStatus) {
      case 'success':
        newStatus = 'active';
        break;
      case 'partial':
        newStatus = 'warning';
        break;
      default:
        newStatus = 'inactive';
    }
    
    // Update server status in database
    await new Promise((resolve, reject) => {
      db.run(
        'UPDATE servers SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [newStatus, serverId],
        function(err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });
    
    // Prepare comprehensive response
    const responseData = {
      server_id: parseInt(serverId),
      server_name: server.name,
      ip_address: server.ip_address,
      port: server.port,
      username: server.username,
      connection_status: connectionStatus,
      server_status: newStatus,
      response_time: responseTime,
      test_timestamp: new Date().toISOString(),
      connection_details: connectionDetails,
      error_message: errorMessage
    };
    
    res.json({
      success: true,
      message: 'Connection test completed',
      data: responseData
    });
    
  } catch (error) {
    console.error('Test connection error:', error);
    res.status(500).json({ 
      error: 'Internal server error during connection test',
      details: error.message 
    });
  }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `${req.method} ${req.originalUrl} is not a valid endpoint`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// ==================== SERVER STARTUP ====================

async function startServer() {
  try {
    await initDatabase();
    
    app.listen(PORT, () => {
      console.log('🚀 SSH & Server Management API');
      console.log('================================');
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`✅ Database: ${DB_PATH}`);
      console.log('================================');
      console.log(`📡 Health check: http://localhost:${PORT}/health`);
      console.log(`📚 API Documentation: See README.md`);
      console.log('================================');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  if (db) {
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err.message);
      } else {
        console.log('✅ Database connection closed');
      }
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

// Start the server
startServer();

module.exports = app;
