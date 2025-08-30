# H96 Edge (Armbian) - Pi-hole + Unbound, Nginx + Homer, WireGuard, Fail2Ban
**Bare-metal, low-write, USB-backed, static IP via Netplan (Ethernet-only)**

This repo sets up an **H96 Pro+ (S912) with Armbian (Bookworm minimal)** as a lightweight LAN edge box:

- **Pi-hole + Unbound** → DNS + ad blocking (Unbound as recursive resolver over TLS)
- **Nginx + Homer** → Dashboard on **http://HOST_IP/**, Pi-hole admin proxied at **/pihole** (and **/admin**)
- **WireGuard** → VPN endpoint on **UDP 51820**
- **Fail2Ban** → Protects SSH & Nginx
- **Static IP** via **Netplan** on **eth0** (Wi-Fi is unsupported on H96 Armbian)
- **USB persistence** → moves write-heavy paths off the SD card

> ⚠️ H96 Pro+ on Armbian has **no Wi-Fi**. This setup assumes **Ethernet (eth0)** only.

---

## Quick Start

On the H96 (Armbian):

```bash
sudo apt-get update -y && sudo apt-get install -y git
git clone https://github.com/tbourn/h96pro-setup.git
cd h96pro-setup
chmod +x h96-setup.sh

# Run with your actual values:
IFACE=eth0 HOST_IP=192.168.1.60 GATEWAY=192.168.1.1 CIDR=24 USB_PART=/dev/sda1 sudo ./h96-setup.sh
```

When it finishes:

- Open **Homer**: `http://192.168.1.60/`
- **Pi-hole admin**: `http://192.168.1.60/pihole` (or `/admin`)
- Set **DNS on your phone/laptop** to **`192.168.1.60`** → **ads blocked** on that device.

> If you don’t control the upstream router, you **cannot** push DNS to the whole network. Set DNS **per device** to the H96 IP.

---

## What the script does

- Installs: `unbound`, `pihole`, `nginx`, `fail2ban`, `wireguard`, `iptables-persistent`, `git`, and utilities
- Configures **Netplan** static IP on `eth0`
- Sets **Pi-hole upstream** to **Unbound** at `127.0.0.1#5335`
- Moves Pi-hole’s embedded web server (**lighttpd**) to **:8081** and proxies via **Nginx :80**
- Deploys **Homer** static site and basic links
- **Offloads writes to USB** (bind-mounts):
  - `/etc/pihole` → `/srv/edge-usb/pihole`
  - `/etc/wireguard` → `/srv/edge-usb/wireguard`
  - `/var/www/homer` → `/srv/edge-usb/homer`
  - `/var/cache/apt` → `/srv/edge-usb/apt-cache`
  - Logs to USB: `nginx`, `lighttpd`, and `pihole-FTL.log`

---

## Configuration (env vars)

Set as environment variables before running the script:

| Var | Default | Meaning |
|---|---|---|
| `IFACE` | `eth0` | Network interface (Ethernet only on H96 Armbian). |
| `HOST_IP` | `192.168.1.60` | Static LAN IP for the H96. |
| `CIDR` | `24` | Subnet bits (24 → 255.255.255.0). |
| `GATEWAY` | `192.168.1.1` | LAN router/gateway. |
| `USB_PART` | `/dev/sda1` | USB partition for persistence (**ext4** recommended). |
| `WG_NET` | `10.13.13.0/24` | WireGuard subnet. |
| `WG_ADDR` | `10.13.13.1/24` | WireGuard server address. |
| `WG_PORT` | `51820` | WireGuard UDP port. |

To discover your USB partition:
```bash
lsblk -o NAME,RM,SIZE,FSTYPE,MOUNTPOINT,TRAN
```

---

## Verify

```bash
# Mounts & binds
mount | egrep 'edge-usb|/etc/pihole|/etc/wireguard|/var/www/homer|/var/cache/apt'

# Services
systemctl status unbound pihole-FTL lighttpd nginx wg-quick@wg0 fail2ban --no-pager
```

---

## Troubleshooting

- **USB not found** → check `lsblk -o NAME,RM,SIZE,FSTYPE,MOUNTPOINT,TRAN` and set `USB_PART` correctly.
- **No ads blocked** → on each device, set DNS to your H96 IP (e.g., `192.168.1.60`).
- **Pi-hole admin** → `http://HOST_IP/pihole` (or `/admin`). Nginx is on :80; lighttpd is moved to :8081.
- **WireGuard from outside** → requires UDP **51820** forwarded from upstream router to your H96 IP.

---

## Uninstall / Revert (manual)

```bash
sudo systemctl disable --now wg-quick@wg0 nginx pihole-FTL unbound fail2ban
sudo sed -i '\|/srv/edge-usb|d' /etc/fstab
sudo sed -i '\|/etc/pihole|d; \|/etc/wireguard|d; \|/var/www/homer|d; \|/var/cache/apt|d' /etc/fstab
sudo mount -a
sudo rm -rf /srv/edge-usb
# Remove netplan file if you want DHCP again:
# sudo rm /etc/netplan/01-static.yaml && sudo netplan apply
```

---

**Enjoy your ad-free LAN device-by-device by setting DNS to your H96 IP.**
