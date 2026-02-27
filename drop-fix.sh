#!/bin/bash

rm -f /etc/default/dropbear
apt remove dropbear -y

sleep 0.5

apt install dropbear -y
wget -q -O /etc/default/dropbear "https://raw.githubusercontent.com/myscpepees/pepe-es/main/source/dropbear"

/etc/init.d/dropbear restart
/etc/init.d/dropbear status
