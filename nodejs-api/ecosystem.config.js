module.exports = {
  apps: [{
    name: 'ssh-api-nodejs',
    script: './app.js',
    cwd: '/opt/ssh-api-nodejs',
    instances: 1,
    exec_mode: 'fork',
    
    // Environment variables
    env: {
      NODE_ENV: 'development',
      PORT: 3000,
      DB_PATH: './database.db'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      DB_PATH: '/opt/ssh-api-nodejs/database.db'
    },
    
    // Logging
    log_file: './logs/combined.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    
    // Process management
    max_restarts: 10,
    min_uptime: '10s',
    max_memory_restart: '1G',
    
    // Monitoring
    watch: false,
    ignore_watch: [
      'node_modules',
      'logs',
      '*.db',
      '*.log',
      '.git'
    ],
    
    // Advanced settings
    autorestart: true,
    kill_timeout: 5000,
    listen_timeout: 8000,
    
    // Auto restart on file changes (development only)
    watch_options: {
      followSymlinks: false,
      usePolling: false
    },
    
    // Instance variables
    instance_var: 'INSTANCE_ID',
    
    // Source map support
    source_map_support: true
  }],

  // Deployment configuration
  deploy: {
    production: {
      user: 'ssh-api',
      host: 'localhost',
      ref: 'origin/main',
      repo: 'git@github.com:your-repo/ssh-api-nodejs.git',
      path: '/opt/ssh-api-nodejs',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
