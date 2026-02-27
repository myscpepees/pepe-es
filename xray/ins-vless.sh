#!/bin/Bash
hosting="https://raw.githubusercontent.com/myscpepees/pepe-es/main/xray/"

wget -q -O /etc/nginx/conf.d/vless.conf "${hosting}vless.conf"
wget -q -O /etc/xray/vless.json "${hosting}vless.json"

cat >/etc/systemd/system/vless.service <<EOF
Description=Xray Vless Custom Path Service
Documentation=https://t.me/xdtunnell
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/vless.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF

systemctl enable vless
systemctl restart nginx vless
