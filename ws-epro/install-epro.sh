#!/bin/bash

hosting="https://raw.githubusercontent.com/myscpepees/pepe-es/main/"

if [[ -d "/ws" ]]; then
    rm -rf /ws
fi

if [[ -e /etc/systemd/system/ws.service ]]; then
systemctl stop ws
systemctl disable ws
rm -f /etc/systemd/system/ws.service
fi

mkdir -p /ws

wget -q -O /ws/ws "${hosting}ws-epro/ws"
chmod +x /ws/ws

cat > /ws/config.yaml <<-EOF
# verbose level 0=info, 1=verbose, 2=very verbose
verbose: 0
listen:

# // SSH
- target_host: 127.0.0.1
  target_port: 109
  listen_port: 10015

# // OpenVPN WS
- target_host: 127.0.0.1
  target_port: 1194
  listen_port: 2095

EOF
chmod 644 /ws/config.yaml

cat > /etc/systemd/system/ws.service <<-EOF
[Unit]
Description=Websocket XDTunnel
Documentation=https://t.me/xdtunnell
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/ws/ws -f /ws/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/ws.service

systemctl daemon-reload
systemctl enable ws.service
systemctl start ws.service
systemctl restart ws.service

rm -f $0
