#!/usr/bin/env bash
set -euo pipefail

# ========= Root check =========
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[!] Run as root (sudo -i or sudo bash h96-setup.sh)"; exit 1
fi

# ========= Configuration =========
: "${TZ:=Europe/Athens}"
: "${IFACE:=eth0}"                    # H96 Armbian = Ethernet only
: "${HOST_IP:=192.168.1.60}"          # static IP for this box
: "${CIDR:=24}"                       # subnet bits (24 = 255.255.255.0)
: "${GATEWAY:=192.168.1.1}"           # upstream router/gateway
: "${WG_NET:=10.13.13.0/24}"          # WireGuard subnet
: "${WG_ADDR:=10.13.13.1/24}"         # WireGuard server IP
: "${WG_PORT:=51820}"                 # WireGuard port
: "${USB_PART:=/dev/sda1}"            # USB partition for persistence (ext4)

echo "[i] IFACE=$IFACE HOST_IP=$HOST_IP/$CIDR GW=$GATEWAY TZ=$TZ"
echo "[i] WireGuard: $WG_ADDR subnet=$WG_NET port=$WG_PORT"
echo "[i] USB_PART=$USB_PART"

# ========= USB sanity checks =========
if ! lsblk -no FSTYPE "$USB_PART" >/dev/null 2>&1; then
  echo "[!] USB partition $USB_PART not found. Run: lsblk -o NAME,RM,SIZE,FSTYPE,MOUNTPOINT,TRAN"; exit 1
fi
USB_FS="$(lsblk -no FSTYPE "$USB_PART")"
USB_UUID="$(blkid -s UUID -o value "$USB_PART" || true)"
if [[ -z "$USB_UUID" ]]; then
  echo "[!] $USB_PART has no UUID. If empty, format once: mkfs.ext4 -L EDGEUSB $USB_PART"; exit 1
fi

# ========= Base packages =========
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl gnupg2 ca-certificates lsb-release openssl \
  zram-tools smartmontools ldnsutils \
  nginx fail2ban unbound wireguard wireguard-tools \
  iptables-persistent

timedatectl set-timezone "$TZ" || true
systemctl enable --now ssh

# ========= Static IP with Netplan (renderer: NetworkManager) =========
echo "[i] Writing Netplan config..."
mkdir -p /etc/netplan
cat >/etc/netplan/01-static.yaml <<EOF
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    ${IFACE}:
      addresses: [${HOST_IP}/${CIDR}]
      routes:
        - to: default
          via: ${GATEWAY}
      nameservers:
        addresses: [127.0.0.1,1.1.1.1]
EOF
chmod 600 /etc/netplan/01-static.yaml
# tighten default file if present (silence warnings)
[[ -f /etc/netplan/armbian-default.yaml ]] && chmod 600 /etc/netplan/armbian-default.yaml || true
netplan apply

# ========= Free port 53 (disable systemd-resolved stub) =========
if grep -q '^#\?DNSStubListener' /etc/systemd/resolved.conf 2>/dev/null; then
  sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
else
  echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
fi
systemctl restart systemd-resolved || true
# Use a public resolver until Pi-hole is ready
echo "nameserver 1.1.1.1" > /etc/resolv.conf

# ========= Unbound (127.0.0.1:5335) =========
mkdir -p /etc/unbound/unbound.conf.d
cat >/etc/unbound/unbound.conf.d/pi-hole.conf <<'CONF'
server:
  verbosity: 1
  interface: 127.0.0.1
  port: 5335
  do-ip6: no
  prefetch: yes
  qname-minimisation: yes
  cache-min-ttl: 120
  cache-max-ttl: 86400
forward-zone:
  name: "."
  forward-tls-upstream: yes
  forward-addr: 1.1.1.1@853#cloudflare-dns.com
  forward-addr: 1.0.0.1@853#cloudflare-dns.com
CONF
# Trust anchor refresh + start
rm -f /var/lib/unbound/root.key || true
unbound-anchor -a /var/lib/unbound/root.key || true
unbound-checkconf /etc/unbound/unbound.conf.d/pi-hole.conf
systemctl enable --now unbound
systemctl restart unbound

# ========= Pi-hole (unattended) =========
if ! command -v pihole >/dev/null 2>&1; then
  curl -sSL https://install.pi-hole.net -o /tmp/install.sh
  PIHOLE_SKIP_OS_CHECK=true bash /tmp/install.sh --unattended
fi

SETUPVARS="/etc/pihole/setupVars.conf"
touch "$SETUPVARS"
grep -q '^PIHOLE_INTERFACE=' "$SETUPVARS" || echo "PIHOLE_INTERFACE=${IFACE}" >>"$SETUPVARS"
grep -q '^IPV4_ADDRESS=' "$SETUPVARS"   || echo "IPV4_ADDRESS=${HOST_IP}/${CIDR}" >>"$SETUPVARS"
sed -i '/^PIHOLE_DNS_/d' "$SETUPVARS"
echo "PIHOLE_DNS_1=127.0.0.1#5335" >>"$SETUPVARS"
grep -q '^WEBPASSWORD=' "$SETUPVARS" || echo "WEBPASSWORD=$(openssl rand -hex 16)" >>"$SETUPVARS"
pihole restartdns || true

# Move lighttpd to 8081 (Nginx will be on :80)
if [[ -f /etc/lighttpd/lighttpd.conf ]]; then
  sed -i 's/^\s*server\.port\s*=.*/server.port = 8081/' /etc/lighttpd/lighttpd.conf
fi
systemctl restart lighttpd || true

# ========= USB persistence (bind mounts) =========
USB_MNT="/srv/edge-usb"
mkdir -p "$USB_MNT"
grep -q "$USB_UUID" /etc/fstab || echo "UUID=$USB_UUID $USB_MNT $USB_FS noatime,nodiratime,defaults 0 2" >>/etc/fstab
mountpoint -q "$USB_MNT" || mount "$USB_MNT"

# Structure on USB
mkdir -p "$USB_MNT"/{pihole,wireguard,homer,apt-cache,logs,logs/lighttpd,logs/nginx}

# Stop services before moving
systemctl stop pihole-FTL || true
systemctl stop lighttpd || true
systemctl stop nginx || true
systemctl stop wg-quick@wg0 || true

# Copy existing data
rsync -aHAX --delete /etc/pihole/     "$USB_MNT/pihole/"     || true
rsync -aHAX --delete /etc/wireguard/  "$USB_MNT/wireguard/"  || true
rsync -aHAX --delete /var/www/homer/  "$USB_MNT/homer/"      || true
rsync -aHAX --delete /var/cache/apt/  "$USB_MNT/apt-cache/"  || true

# Bind mounts
add_bind() { local src="$1" dst="$2"; grep -q " $dst " /etc/fstab || echo "$src $dst none bind 0 0" >>/etc/fstab; }
add_bind "$USB_MNT/pihole"     /etc/pihole
add_bind "$USB_MNT/wireguard"  /etc/wireguard
add_bind "$USB_MNT/homer"      /var/www/homer
add_bind "$USB_MNT/apt-cache"  /var/cache/apt

mount -a

# ========= Nginx + Homer (logs to USB) =========
rm -f /etc/nginx/sites-enabled/default
cat >/etc/nginx/sites-available/edge <<NGX
server {
  listen 80;
  server_name _;

  access_log $USB_MNT/logs/nginx/access.log;
  error_log  $USB_MNT/logs/nginx/error.log;

  root /var/www/homer;
  index index.html;

  location / { try_files \$uri \$uri/ /index.html; }

  # Pi-hole admin via lighttpd :8081
  location /pihole/ {
    proxy_pass http://127.0.0.1:8081/admin/;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
  }
  location /admin/ {
    proxy_pass http://127.0.0.1:8081/admin/;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
NGX
ln -sf /etc/nginx/sites-available/edge /etc/nginx/sites-enabled/edge

# Fetch Homer (static) if not present
mkdir -p /var/www/homer
if [[ ! -f /var/www/homer/index.html ]]; then
  URL=$(curl -s https://api.github.com/repos/bastienwirtz/homer/releases/latest | grep browser_download_url | grep -m1 tar.gz | cut -d\" -f4)
  curl -L "$URL" -o /tmp/homer.tar.gz
  tar -xzf /tmp/homer.tar.gz -C /var/www/homer --strip-components=1
fi
mkdir -p /var/www/homer/assets
cat >/var/www/homer/assets/config.yml <<YML
title: "H96 Edge"
subtitle: "LAN Gateway"
links:
  - name: Pi-hole
    url: http://$HOST_IP/pihole
  - name: WireGuard
    url: http://$HOST_IP
  - name: Q9550 Grafana
    url: http://192.168.1.50:3000
  - name: Q9550 Plex
    url: http://192.168.1.50:32400/web
YML

# ========= Pi-hole logs → USB; lighttpd logs → USB =========
mkdir -p /etc/pihole/logs
FTL_CONF="/etc/pihole/pihole-FTL.conf"
grep -q '^LOGFILE=' "$FTL_CONF" 2>/dev/null && sed -i '/^LOGFILE=/d' "$FTL_CONF" || true
echo "LOGFILE=/etc/pihole/logs/pihole-FTL.log" >> "$FTL_CONF"

LTPD_CONF="/etc/lighttpd/lighttpd.conf"
if [[ -f "$LTPD_CONF" ]]; then
  grep -q '^accesslog\.filename' "$LTPD_CONF" \
    && sed -i "s|^accesslog\.filename.*|accesslog.filename = \"$USB_MNT/logs/lighttpd/access.log\"|" "$LTPD_CONF" \
    || echo "accesslog.filename = \"$USB_MNT/logs/lighttpd/access.log\"" >> "$LTPD_CONF"
  grep -q '^server\.errorlog' "$LTPD_CONF" \
    && sed -i "s|^server\.errorlog.*|server.errorlog = \"$USB_MNT/logs/lighttpd/error.log\"|" "$LTPD_CONF" \
    || echo "server.errorlog = \"$USB_MNT/logs/lighttpd/error.log\"" >> "$LTPD_CONF"
fi

# ========= Fail2Ban (read Nginx logs from USB path) =========
mkdir -p /etc/fail2ban/jail.d
cat >/etc/fail2ban/jail.d/nginx-usb.conf <<EOF
[nginx-http-auth]
enabled = true
logpath = $USB_MNT/logs/nginx/access.log

[nginx-botsearch]
enabled = true
logpath = $USB_MNT/logs/nginx/access.log

[sshd]
enabled = true
EOF

# ========= WireGuard =========
mkdir -p /etc/wireguard
umask 077
[[ -f /etc/wireguard/server.key ]] || wg genkey | tee /etc/wireguard/server.key | wg pubkey >/etc/wireguard/server.pub
SERVER_PRIV=$(cat /etc/wireguard/server.key)
cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $WG_ADDR
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
SaveConfig = true
EOF

cat >/etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
EOF
sysctl --system

iptables -t nat -C POSTROUTING -s $WG_NET -o $IFACE -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s $WG_NET -o $IFACE -j MASQUERADE
netfilter-persistent save

# ========= Bring services up =========
systemctl restart unbound
systemctl restart lighttpd
systemctl restart fail2ban
systemctl enable --now wg-quick@wg0
systemctl restart nginx

# Point local resolver to Pi-hole
echo "nameserver 127.0.0.1" >/etc/resolv.conf || true

echo
echo "============================================================"
echo "[✓] Setup complete."
echo "SSH:               ssh $(id -un)@$HOST_IP"
echo "Homer dashboard:   http://$HOST_IP"
echo "Pi-hole admin:     http://$HOST_IP/pihole  (or /admin)"
echo "DNS on *your device*: set DNS to $HOST_IP to block ads"
echo "WireGuard (LAN):   UDP $WG_PORT on $HOST_IP (needs port-forward upstream for remote use)"
echo "USB mounts:        $USB_MNT -> /etc/pihole, /etc/wireguard, /var/www/homer, /var/cache/apt"
echo "Logs on USB:       $USB_MNT/logs/nginx/*, $USB_MNT/logs/lighttpd/*, /etc/pihole/logs/pihole-FTL.log"
echo "============================================================"
