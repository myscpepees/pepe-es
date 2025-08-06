#!/bin/bash
clear

apt update -y
apt install ruby -y
apt install curl wget -y
apt install wondershaper -y

NC='\033[0m'
rbg='\033[41;37m'
r='\033[1;91m'
g='\033[1;92m'
y='\033[1;93m'
u='\033[0;35m'
c='\033[0;96m'
w='\033[1;97m'
a='\033[0;34m'

function lane_atas() {
echo -e "${c}┌──────────────────────────────────────────┐${NC}"
}
function lane_bawah() {
echo -e "${c}└──────────────────────────────────────────┘${NC}"
}

mkdir -p /etc/xray

# Pengecekan apakah file isp sudah ada dan pengecekan apakah file isp kosong
if [[ ! -f /etc/xray/isp ]] || [[ ! -s /etc/xray/isp ]]; then
    curl -s ipinfo.io/org?token=7a814b6263b02c -o /etc/xray/isp
fi

# Pengecekan apakah file city sudah ada dan pengecekan apakah file city kosong
if [[ ! -f /etc/xray/city ]] || [[ ! -s /etc/xray/city ]]; then
    curl -s ipinfo.io/city?token=7a814b6263b02c -o /etc/xray/city
fi

# Pengecekan apakah file ipvps sudah ada dan pengecekan apakah file ipvps kosong
if [[ ! -f /root/.ipvps ]] || [[ ! -s /root/.ipvps ]]; then
    curl -s ipv4.icanhazip.com -o /root/.ipvps
fi

ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
IP=$(cat /root/.ipvps)

# // Checking Os Architecture
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
echo -ne
else
echo -e "${r} Your Architecture Is Not Supported ( ${y}$( uname -m )${NC} )"
exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi

url_izin="https://raw.githubusercontent.com/myscpepees/pepe-es/main/ip"
username=$(wget -qO- $url_izin | grep $IP | awk '{print $2}')
exp=$(wget -qO- $url_izin | grep $IP | awk '{print $3}')

d1=$(date -d "$exp" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
# VPS Information
DATE=$(date +'%Y-%m-%d')
datediff() {
d1=$(date -d "$1" +%s)
d2=$(date -d "$2" +%s)
echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""
Info="(${g}Active${NC})"
Error="(${r}Expired${NC})"
today=`date -d "0 days" +"%Y-%m-%d"`
Exp1=$(wget -qO- $url_izin | grep $IP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi

#hosting="https://pub-e455c3976e3144b7b75dac87bb75d5b9.r2.dev/naura/"

hosting="https://raw.githubusercontent.com/myscpepees/pepe-es/main/"

function print_install() {
clear
lane_atas
echo -e "${y}  $1 ${NC}"
lane_bawah
sleep 0.5
}

function print_error() {
echo -e "${r} ${rbg} $1 ${NC}"
}

function print_success() {
if [[ 0 -eq $? ]]; then
lane_atas
echo -e "${g}   $1 berhasil dipasang"
lane_bawah
fi
}

function first_setup(){
print_install "Membuat direktori xray"
    mkdir -p /etc/xray
    touch /etc/xray/domain
    mkdir -p /var/log/xray
    chown www-data:www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    mkdir -p /var/lib/kyt >/dev/null 2>&1
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
}

function base_package() {
clear
apt update -y
apt install sudo -y
sudo apt-get clean all
apt install -y debconf-utils
apt install p7zip-full at -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
apt-get autoremove -y
apt install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install nginx iptables iptables-persistent netfilter-persistent libxml-parser-perl squid screen curl jq bzip2 gzip coreutils zip unzip rsyslog net-tools sed bc apt-transport-https build-essential dirmngr libxml-parser-perl lsof openvpn easy-rsa fail2ban tmux squid dropbear socat cron bash-completion ntpdate xz-utils apt-transport-https chrony pkg-config bison make git speedtest-cli p7zip-full zlib1g-dev python-is-python3 python3-pip build-essential squid libcurl4-openssl-dev bsdmainutils
sudo apt-get autoclean -y >/dev/null 2>&1
audo apt-get -y --purge removd unscd >/dev/null 2>&1
sudo apt-get -y --purge remove samba* >/dev/null 2>&1
sudo apt-get -y --purge remove bind9* >/dev/null 2>&1
sudo apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1

source /etc/os-release
OS="$ID $VERSION_ID"
if [[ "$OS" == "debian 12" || "$OS" == "ubuntu 24.04" || "$OS" == "ubuntu 24.10" ]]; then
    sudo apt update
    sudo apt install -y python3-venv python3-pip
    sudo python3 -m venv /opt/gdown-venv
    sudo /opt/gdown-venv/bin/pip install gdown
    sudo ln -sf /opt/gdown-venv/bin/gdown /usr/local/bin/gdown
else
    pip install gdown
fi

print_success "Packet Yang Dibutuhkan"
}

function pasang_domain() {
clear
lane_atas
echo -e "${c}│ ${w}               DOMAIN MENU               ${c}│${NC}"
lane_bawah
lane_atas
echo -e "${c}│${NC} 1. ${w}Gunakan Domain Sendiri ${NC}"
echo -e "${c}│${NC} 2. ${w}Gunakan Domain Dari Script ${NC}"
lane_bawah
read -p " Pilih Opsi [ 1 - 2 ] : " host
echo ""
if [[ $host == "1" ]]; then
echo -e "   \e[1;32mMasukan Domain Kamu!$NC"
host1_input() {
read -p "   Subdomain: " host1
if [[ -z $host1 ]]; then
host1_input
fi
}
host1_input
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
echo "Proses pointing"
wget -q -O cf.sh "${hosting}source/cf.sh"
chmod +x cf.sh
./cf.sh
else
clear
echo -e " Pilih opsi hanya 1 - 2 !!!!"
sleep 3
pasang_domain
fi
}

function pasang_ssl() {
clear
print_install "Memasang SSL Pada Domain"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /etc/xray/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl -s "https://acme-install.netlify.app/acme.sh" -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
print_success "SSL Certificate"
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
mkdir -p /etc/bot
mkdir -p /etc/usr
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
mkdir -p /etc/kyt/limit/vmess/ip
mkdir -p /etc/kyt/limit/vless/ip
mkdir -p /etc/kyt/limit/trojan/ip
mkdir -p /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/ssh
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
}
function install_xray() {
clear
print_install "Service Xray"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data:www-data $domainSock_dir

#latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 24.10.31
wget -q -O /etc/xray/config.json "${hosting}xray/config.json"
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i "s/xxx/${uuid}/g" /etc/xray/config.json
domain=$(cat /etc/xray/domain)
IPVPS=$(cat /etc/xray/ipvps)
print_success "Service Xray"
clear
print_install "Memasang Konfigurasi Packet"
wget -q -O /etc/nginx/conf.d/xray.conf "${hosting}source/xray.conf"
rm -f /etc/squid/squid.conf
wget -q -O /etc/squid/squid.conf "${hosting}source/squid.conf"
sed -i "s/xxxxxxxxx/${IP}/g" /etc/squid/squid.conf
sed -i "s/newhost/$(cat /etc/xray/domain)/g" /etc/squid/squid.conf

wget -q -O /etc/nginx/nginx.conf "${hosting}source/nginx.conf"
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://t.me/xdtunnell
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
print_success "Konfigurasi Packet"
}

function ssh(){
clear
print_install "Memasang Password SSH"
wget -q -O /etc/pam.d/common-password "${hosting}source/password"
chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

cd
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}

function udp_mini(){
clear
print_install "Memasang Service BadVPN UDP"
cd
wget -q -O /usr/sbin/badvpn "${hosting}source/badvpn"
chmod +x /usr/sbin/badvpn

create_service() {
    local name=$1
    local description=$2
    local exec_start=$3

cat >/etc/systemd/system/udp-mini-${name}.service <<EOF
[Unit]
Description=${description} %i
Documentation=https://t.me/xdtunnell
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
#ExecStart=/usr/sbin/badvpn --listen-addr 127.0.0.1:7100 --listen-addr 127.0.0.1:7200 --listen-addr 127.0.0.1:7300 --max-clients 500
ExecStart=${exec_start}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
}

create_service "1" "XDTunnel Service" "/usr/sbin/badvpn --listen-addr 127.0.0.1:7100 --max-clients 1000"
create_service "2" "XDTunnel Service" "/usr/sbin/badvpn --listen-addr 127.0.0.1:7200 --max-clients 1000"
create_service "3" "XDTunnel Service" "/usr/sbin/badvpn --listen-addr 127.0.0.1:7300 --max-clients 1000"
print_success "BadVPN UDP Service"
}

function ssh_slow(){
clear
print_install "Memasang modul SlowDNS Server"
wget -q -O nameserver "${hosting}slowdns/nameserver"
chmod +x nameserver
bash nameserver && rm -f nameserver
print_success "SlowDNS"
}

function ins_SSHD(){
clear
print_install "Memasang SSHD"
wget -q -O /etc/ssh/sshd_config "${hosting}source/sshd"
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}

function ins_dropbear(){
clear
print_install "Menginstall Dropbear"
apt-get install dropbear -y
sudo dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key
sudo chmod 600 /etc/dropbear/dropbear_dss_host_key

cat<<EOF>>/etc/default/dropbear
# The TCP port that Dropbear listens on
DROPBEAR_PORT=109

# Receive window size - this is a tradeoff between memory and network performance
DROPBEAR_RECEIVE_WINDOW=65536

# Any additional arguments for Dropbear.  For instead set
#
DROPBEAR_EXTRA_ARGS="-b /etc/issue.net -p 143 -I 60"
#
# to specify an optional banner file containing a message to be sent to
DROPBEAR_BANNER="/etc/issue.net"
# clients before they connect; or
#
#   DROPBEAR_EXTRA_ARGS="-p 109""-r /etc/dropbear/rsa_host_key -r /etc/dropbear/ed25519_host_key"
#
# to specify custom host keys.  See dropbear(8) for possible values.
#DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"""

EOF
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

wget -q -O rsyslog_install.sh "${hosting}rsyslog_install.sh"
chmod +x rsyslog_install.sh
./rsyslog_install.sh

print_success "Dropbear"
}

function ins_vnstat(){
clear
print_install "Menginstall Vnstat"
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}

function ins_openvpn(){
clear
print_install "Menginstall OpenVPN"
wget -q -O openvpn "${hosting}source/openvpn"
chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}

function ins_backup(){
clear
print_install "Memasang Backup Server"
apt install rclone -y
printf "q\n" | rclone config

rm -f /root/.config/rclone/rclone.conf

cat >/root/.config/rclone/rclone.conf <<EOF
[dr]
type = drive
scope = drive
token = {"access_token":"ya29.a0AS3H6NwTbeRqRT1lOxUHkwBWMz2yOVdF-Xpf4_SzVwc9pnHqgbteD0xnaT6u-3MqAEE7m3_yy2qpPN4L1W_mvVlelnP4dLOp3jc6BsV2-R0j481PnNl0s_rAvbP9ozLDBi2ycqLjF2MZ5Vr00a71nRbrU8ShhgbfqXT2OPYMaCgYKAUoSARISFQHGX2Mi9o0YnSMJvUOOCKaZLvbfyA0175","token_type":"Bearer","refresh_token":"1//0gcVdmncrkDjHCgYIARAAGBASNwF-L9IrWt_cE5Q1_jfh6nURV9OzOKpHhZGqtU9cvky7HKcPJKDBoAuXsXTdChy4UXLiQH2kdRs","expiry":"2025-07-11T09:31:26.357833999Z","expires_in":3599}
EOF

cd /bin
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper

wget -q -O /etc/ipserver "${hosting}source/ipserver" && bash /etc/ipserver
print_success "Backup Server"
}

function ins_swab(){
clear
print_install "Memasang Swap"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1


dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

# > Singkronisasi jam
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v

wget -q -O enhanced.sh "${hosting}enhanced.sh"
chmod +x enhanced.sh
./enhanced.sh &>/dev/null
rm -f enhanced.sh

wget -q ${hosting}source/bbr.sh
chmod +x bbr.sh && ./bbr.sh
print_success "Swap"
}

function ins_Fail2ban(){
clear
apt -y install fail2ban
/etc/init.d/fail2ban restart
/etc/init.d/fail2ban status

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
rm -rf /usr/local/ddos
fi

mkdir -p /usr/local/ddos

echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

wget -q -O /etc/issue.net "${hosting}source/banner.com"
}

function ins_epro(){
clear
print_install "Menginstall ePro WebSocket Proxy"
wget -q -O install-epro.sh "${hosting}ws-epro/install-epro.sh"
chmod +x install-epro.sh
./install-epro.sh

wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1

iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy"

cd
if [ -d /etc/udp ];then
rm -rf /etc/udp
fi
mkdir -p /etc/udp

# install udp-custom
echo;echo -e "[$(date)] Processed Install udp custom";echo
sleep 2
wget -q -O /etc/udp/udp-custom "${hosting}ssh/udp-custom-linux-amd64"
wget -q -O /etc/udp/config.json "${hosting}ssh/config.json"
chmod 777 /etc/udp/config.json
chmod +x /etc/udp/udp-custom

cat > /etc/systemd/system/udp-custom.service <<-END
[Unit]
Description=UDP Custom Service
Documentation=https://t.me/xdtunnell
After=network.target nss-lookup.target

[Service]
User=root
Type=simple
ExecStart=/etc/udp/udp-custom server -exclude 1,54,55,1000,65535
WorkingDirectory=/etc/udp/
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
END

}

function menu(){
clear
mkdir -p /cache
mkdir -p /usr/local/style
cd /cache
wget -q -O menu.zip "${hosting}v1/menu.zip"
# Password: scnaurav1allos0191
7z x -pscnaurav1allos0191 menu.zip >/dev/null 2>&1
chmod +x menu/*
mv menu/*.sh /usr/local/style/
mv menu/* /usr/local/sbin/
cd
rm -rf /cache
wget -qO- ${hosting}version > /root/.versi

wget -q -O /tmp/quota.sh "${hosting}quota/quota.sh"
chmod +x /tmp/quota.sh
bash /tmp/quota.sh

}

function profile(){
clear

cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu xdxl
EOF

cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 0 * * * root /usr/local/sbin/xp
	END
cat >/etc/cron.d/auto_newbackup2 <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		59 23 * * * root /usr/local/sbin/bkpusr
	END
	cat >/etc/cron.d/logclean <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/19 * * * * root /usr/local/sbin/clearlog
		END
    chmod 644 /root/.profile
	
    cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END



cat >/usr/local/bin/log_udp <<-END
#!/bin/bash
systemctl restart udp-custom
END
chmod +x /usr/local/bin/log_udp

cat >/etc/cron.d/log.nginx <<-END
/var/log/nginx/stream.log
/var/log/nginx/access.log
END

cat >/etc/cron.d/log.xray <<-END
0 0 * * * root echo -n > /var/log/xray/access.log
59 23 * * * root echo -n > /var/log/xray/access.log
*/15 * * * * root echo -n > /var/log/xray/error.log
END

cat >/etc/cron.d/log.ssh <<-END
59 23 * * * root echo -n > /var/log/auth.log
1 2 * * * root /usr/local/bin/log_udp
END

service cron restart
cat >/home/daily_reboot <<-END
5
END

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
}

function enable_services(){
clear
print_install "Enable All Service"
echo
systemctl daemon-reload
services=(
    "nginx"
    "xray"
    "rc-local"
    "dropbear"
    "openvpn"
    "cron"
    "netfilter-persistent"
    "fail2ban"
    "rc-local"
    "ws"
    "udp-mini-1"
    "udp-mini-2"
    "udp-mini-3"
    "udp-custom"
    "stunnel4"
)
for service in "${services[@]}"; do
  systemctl enable $service
  echo -ne " Enable service $service...\r"
  sleep 1
  echo -ne " Enable service $service...$green Done! $neutral\n"
done

print_success "Enable Service"
}

function restart_services(){
clear
print_install "Restart All Service"
echo
systemctl daemon-reload
services=(
    "nginx"
    "xray"
    "rc-local"
    "dropbear"
    "openvpn"
    "cron"
    "netfilter-persistent"
    "fail2ban"
    "rc-local"
    "ws"
    "udp-mini-1"
    "udp-mini-2"
    "udp-mini-3"
    "udp-custom"
    "stunnel4"
)
for service in "${services[@]}"; do
  systemctl restart $service
  echo -ne " Restart service $service...\r"
  sleep 1
  echo -ne " Restart service $service...$green Done! $neutral\n"
done

print_success "Restart All Service"
}

# Fingsi Install Script
function install_with_input_domain(){
clear
first_setup
base_package
make_folder_xray
pasang_domain
password_default
pasang_ssl
install_xray
ssh
udp_mini
ssh_slow
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
ins_epro
menu
profile
enable_services
restart_services
restart_system
}

# Fingsi Install Script
function install_with_no_input_domain(){
clear
first_setup
base_package
make_folder_xray
password_default
pasang_ssl
install_xray
ssh
udp_mini
ssh_slow
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
ins_epro
menu
profile
enable_services
restart_services
}

data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")
useexp=$(wget -qO- $url_izin | grep $IP | awk '{print $3}')
if [[ $useexp == "lifetime" || $useexp == "Lifetime" ]]; then
echo -ne
else
  if [[ $date_list < $useexp ]]; then
   echo -ne
   else
    curl -s https://raw.githubusercontent.com/myscpepees/pepe-es/main/invalid.sh | bash
    #exit 0
  fi
fi

if [[ $1 ]]; then
mkdir -p /etc/xray
echo "${1}" > /etc/xray/domain
echo "${1}" > /root/domain
echo "IP=" >> /var/lib/kyt/ipvps.conf
install_with_no_input_domain
else
install_with_input_domain
fi

if [[ "${2}" == "naura" ]]; then
echo "Naura Engineer" > /etc/.license
elif [[ "${2}" == "xdxl" ]]; then
echo "Xdxl Store" > /etc/.license
else
echo "Naura Engineer" > /etc/.license
fi

history -c
echo "unset HISTFILE" >> /etc/profile

cd

wget -q -O drop-fix.sh "${hosting}drop-fix.sh" && chmod +x drop-fix.sh && ./drop-fix.sh

systemctl restart dropbear

wget -q -O ins-vless.sh "${hosting}xray/ins-vless.sh" && chmod +x ins-vless.sh && bash ins-vless.sh && rm -f ins-vless.sh

rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/domain
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf $0
clear
#sudo hostnamectl set-hostname $username

##CHATID="-1002581802863"
##KEY="7711319043:AAFTyYqgRnNwfVwcB02_wVsaYi-hEvAqjp0"
##URL="https://api.telegram.org/bot$KEY/sendMessage"
##TEXT="
##<code>────────────────────</code>
##<b>☘️ AUTOSCRIPT PREMIUM ☘️</b>
##<code>────────────────────</code>
##<code>Client  :</code> <code>$username</code>
##<code>ISP     :</code> <code>$ISP</code>
##<code>Country :</code> <code>$CITY</code>
##<code>Time    :</code> <code>$(date)</code>
##<code>Expired :</code> <code>$exp</code>
##<code>────────────────────</code>
##Automatic Notifications From
##XDTunnel Bot
##"'&reply_markup={"inline_keyboard":[[{"text":" ᴏᴡɴᴇʀ ","url":"https://t.me/xdxl_real"}]]}' 
    curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null

##echo -e "${g}Script Successfull Installed ${NC}"
echo ""
sleep 3
reboot