#!/bin/bash

# SSH & Server Management API Node.js Installer
# This script will install and configure the Node.js API

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
API_DIR="/opt/ssh-api-nodejs"
SERVICE_NAME="ssh-api-nodejs"
API_USER="ssh-api"
NODE_VERSION="18"

print_header() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "    SSH & Server Management API Node.js Installer"
    echo "=================================================="
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    print_status "Checking system requirements..."
    
    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        print_status "Installing curl..."
        apt update
        apt install -y curl
    fi
    
    # Check if Node.js is installed
    if ! command -v node &> /dev/null; then
        print_status "Installing Node.js ${NODE_VERSION}..."
        curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
        apt install -y nodejs
    else
        NODE_CURRENT=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$NODE_CURRENT" -lt "$NODE_VERSION" ]; then
            print_warning "Node.js version $NODE_CURRENT detected. Upgrading to version $NODE_VERSION..."
            curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
            apt install -y nodejs
        fi
    fi
    
    # Check if npm is installed
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed"
        exit 1
    fi
    
    # Install PM2 globally
    if ! command -v pm2 &> /dev/null; then
        print_status "Installing PM2..."
        npm install -g pm2
    fi
    
    print_status "System requirements check completed"
    print_status "Node.js version: $(node --version)"
    print_status "npm version: $(npm --version)"
}

create_user() {
    if ! id "$API_USER" &>/dev/null; then
        print_status "Creating user $API_USER..."
        useradd -r -s /bin/false -d "$API_DIR" "$API_USER"
    else
        print_status "User $API_USER already exists"
    fi
}

install_api() {
    print_status "Installing API files..."
    
    # Create API directory
    mkdir -p "$API_DIR"
    
    # Copy API files
    cp package.json "$API_DIR/"
    cp app.js "$API_DIR/"
    cp test.js "$API_DIR/"
    cp .env.example "$API_DIR/"
    cp README.md "$API_DIR/"
    
    # Create .env file if it doesn't exist
    if [ ! -f "$API_DIR/.env" ]; then
        cp "$API_DIR/.env.example" "$API_DIR/.env"
        print_warning "Please edit $API_DIR/.env with your configuration"
    fi
    
    # Install dependencies
    print_status "Installing Node.js dependencies..."
    cd "$API_DIR"
    npm install --production
    
    # Create logs directory
    mkdir -p "$API_DIR/logs"
    
    # Set permissions
    chown -R "$API_USER:$API_USER" "$API_DIR"
    chmod +x "$API_DIR/app.js"
    
    print_status "API installation completed"
}

install_pm2_service() {
    print_status "Installing PM2 service..."
    
    # Create PM2 ecosystem file
    cat > "$API_DIR/ecosystem.config.js" << EOF
module.exports = {
  apps: [{
    name: '$SERVICE_NAME',
    script: './app.js',
    cwd: '$API_DIR',
    user: '$API_USER',
    instances: 1,
    exec_mode: 'fork',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    log_file: '$API_DIR/logs/combined.log',
    out_file: '$API_DIR/logs/out.log',
    error_file: '$API_DIR/logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    max_restarts: 10,
    min_uptime: '10s',
    max_memory_restart: '1G',
    watch: false,
    ignore_watch: ['node_modules', 'logs', '*.db']
  }]
};
EOF
    
    # Start with PM2
    cd "$API_DIR"
    sudo -u "$API_USER" pm2 start ecosystem.config.js
    
    # Save PM2 configuration
    sudo -u "$API_USER" pm2 save
    
    # Setup PM2 startup
    pm2 startup systemd -u "$API_USER" --hp "$API_DIR"
    
    print_status "PM2 service installed and configured"
}

install_systemd_service() {
    print_status "Installing systemd service as backup..."
    
    # Create systemd service file
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=SSH & Server Management API Node.js
After=network.target
Wants=network.target

[Service]
Type=simple
User=$API_USER
Group=$API_USER
WorkingDirectory=$API_DIR
Environment=NODE_ENV=production
Environment=PORT=3000
ExecStart=/usr/bin/node $API_DIR/app.js
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=on-failure
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$API_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_status "Systemd service installed and enabled"
}

setup_firewall() {
    print_status "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 3000/tcp
        print_status "UFW rule added for port 3000"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=3000/tcp
        firewall-cmd --reload
        print_status "Firewalld rule added for port 3000"
    else
        print_warning "No firewall detected. Please manually open port 3000"
    fi
}

configure_nginx() {
    read -p "Do you want to configure Nginx reverse proxy? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v nginx &> /dev/null; then
            print_status "Configuring Nginx reverse proxy..."
            
            cat > "/etc/nginx/sites-available/ssh-api-nodejs" << EOF
server {
    listen 80;
    server_name your-domain.com;  # Change this to your domain
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:3000/health;
        access_log off;
    }
}
EOF
            
            # Enable site
            ln -sf /etc/nginx/sites-available/ssh-api-nodejs /etc/nginx/sites-enabled/
            nginx -t && systemctl reload nginx
            
            print_status "Nginx configuration completed"
            print_warning "Please update server_name in /etc/nginx/sites-available/ssh-api-nodejs"
        else
            print_warning "Nginx not found. Skipping reverse proxy configuration"
        fi
    fi
}

setup_ssl() {
    read -p "Do you want to setup SSL with Let's Encrypt? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v certbot &> /dev/null; then
            read -p "Enter your domain name: " domain
            if [ ! -z "$domain" ]; then
                print_status "Setting up SSL for $domain..."
                certbot --nginx -d "$domain" --non-interactive --agree-tos --email admin@"$domain"
                print_status "SSL certificate installed for $domain"
            fi
        else
            print_status "Installing certbot..."
            apt install -y certbot python3-certbot-nginx
            read -p "Enter your domain name: " domain
            if [ ! -z "$domain" ]; then
                print_status "Setting up SSL for $domain..."
                certbot --nginx -d "$domain" --non-interactive --agree-tos --email admin@"$domain"
                print_status "SSL certificate installed for $domain"
            fi
        fi
    fi
}

create_management_scripts() {
    print_status "Creating management scripts..."
    
    # Create start script
    cat > "$API_DIR/start.sh" << EOF
#!/bin/bash
cd $API_DIR
sudo -u $API_USER pm2 start ecosystem.config.js
echo "✅ SSH API Node.js started"
EOF
    
    # Create stop script
    cat > "$API_DIR/stop.sh" << EOF
#!/bin/bash
cd $API_DIR
sudo -u $API_USER pm2 stop $SERVICE_NAME
echo "✅ SSH API Node.js stopped"
EOF
    
    # Create restart script
    cat > "$API_DIR/restart.sh" << EOF
#!/bin/bash
cd $API_DIR
sudo -u $API_USER pm2 restart $SERVICE_NAME
echo "✅ SSH API Node.js restarted"
EOF
    
    # Create status script
    cat > "$API_DIR/status.sh" << EOF
#!/bin/bash
cd $API_DIR
sudo -u $API_USER pm2 status $SERVICE_NAME
EOF
    
    # Create logs script
    cat > "$API_DIR/logs.sh" << EOF
#!/bin/bash
cd $API_DIR
sudo -u $API_USER pm2 logs $SERVICE_NAME --lines 50
EOF
    
    # Make scripts executable
    chmod +x "$API_DIR"/*.sh
    chown "$API_USER:$API_USER" "$API_DIR"/*.sh
    
    print_status "Management scripts created"
}

run_tests() {
    read -p "Do you want to run API tests? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Running API tests..."
        cd "$API_DIR"
        
        # Install test dependencies
        npm install --save-dev jest supertest
        
        # Wait for API to start
        sleep 5
        
        # Run tests
        npm test
        
        print_status "API tests completed"
    fi
}

show_completion_info() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "           Installation Completed!"
    echo "=================================================="
    echo -e "${NC}"
    echo
    echo "API Directory: $API_DIR"
    echo "Service Name: $SERVICE_NAME"
    echo "API User: $API_USER"
    echo "Port: 3000"
    echo
    echo "Management Commands:"
    echo "  Start API:    $API_DIR/start.sh"
    echo "  Stop API:     $API_DIR/stop.sh"
    echo "  Restart API:  $API_DIR/restart.sh"
    echo "  Check Status: $API_DIR/status.sh"
    echo "  View Logs:    $API_DIR/logs.sh"
    echo
    echo "PM2 Commands:"
    echo "  pm2 status $SERVICE_NAME"
    echo "  pm2 logs $SERVICE_NAME"
    echo "  pm2 restart $SERVICE_NAME"
    echo "  pm2 stop $SERVICE_NAME"
    echo
    echo "Systemd Commands (backup):"
    echo "  systemctl status $SERVICE_NAME"
    echo "  systemctl start $SERVICE_NAME"
    echo "  systemctl stop $SERVICE_NAME"
    echo "  journalctl -u $SERVICE_NAME -f"
    echo
    echo "Next steps:"
    echo "1. Edit configuration: nano $API_DIR/.env"
    echo "2. API is already running via PM2"
    echo "3. Check status: $API_DIR/status.sh"
    echo "4. View logs: $API_DIR/logs.sh"
    echo
    echo "API Endpoints:"
    echo "  Health Check: curl http://localhost:3000/health"
    echo "  Add Admin: curl -X POST http://localhost:3000/admin/add -H 'Content-Type: application/json' -d '{\"user_id\":\"YOUR_TELEGRAM_USER_ID\"}'"
    echo
    echo "Documentation: $API_DIR/README.md"
    echo
}

main() {
    print_header
    
    check_root
    check_system
    create_user
    install_api
    install_pm2_service
    install_systemd_service
    setup_firewall
    configure_nginx
    setup_ssl
    create_management_scripts
    run_tests
    
    show_completion_info
}

# Run main function
main "$@"
