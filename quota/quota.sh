#!/bin/bash

hosting="https://raw.githubusercontent.com/myscpepees/pepe-es/main/quota"

wget -q -O /usr/sbin/usqu "${hosting}/usqu"
chmod +x /usr/sbin/usqu

wget -q -O /etc/systemd/system/usqu.service "${hosting}/usqu.service"

systemctl enable usqu
systemctl restart usqu