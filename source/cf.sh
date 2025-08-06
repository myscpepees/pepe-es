#!/bin/bash
DOMAIN=vip-server.web.id
apt update
apt install jq curl -y
sub=vpn`</dev/urandom tr -dc 0-9 | head -c5`
dns=${sub}.${DOMAIN}
CF_KEY=ce493b81967366a8b0bf15fc92a804c2101a7
CF_ID=fadliwaykanan@gmail.com
set -euo pipefail
echo ""
sleep 1
if [[ -f /root/.ipvps ]]; then
IP=$(cat /root/.ipvps)
elif [[ -f /root/.myip ]]; then
IP=$(cat /root/.myip)
else
IP=$(curl -s ipv4.icanhazip.com)
fi
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${dns}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD}" -le 10 ]]; then
     RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${dns}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records/${RECORD}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${dns}'","content":"'${IP}'","ttl":120,"proxied":false}')

echo "$dns" > /etc/xray/domain
rm -f "$0"
