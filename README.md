# vpskit

Autoscript modern për VPN/proxy në VPS, me Xray-core dhe sing-box: Reality, XHTTP,
Hysteria2, TUIC, AnyTLS, Shadowsocks-2022, si dhe SSH-WS/SSL, WireGuard e OpenVPN.

Repo: https://github.com/agjetaj/vpskit

## Sistemet e mbështetura

| OS | Versionet |
|---|---|
| Debian | 11, 12, 13 (trixie) |
| Ubuntu | 22.04, 24.04, 25.04, 25.10, 26.04 |
| CPU | amd64 (x86_64), arm64 (aarch64) |

Kërkohet KVM, jo OpenVZ/LXC pa `/dev/net/tun`, plus systemd dhe një domain që tregon IP-në e serverit.

## Protokollet dhe portat

| Shërbimi | Core | Porta |
|---|---|---|
| VLESS + Reality + Vision | Xray | TCP 8443 |
| VLESS XHTTP (TLS, h2) | Xray (pas nginx) | TCP 443 `/xhttp` |
| VLESS / VMess / Trojan WebSocket | Xray (pas nginx) | TCP 443 (TLS), 80 (pa TLS): `/vless` `/vmess` `/trojan` |
| Hysteria2 (+ port hopping) | sing-box | UDP 443 (+ UDP 20000-40000) |
| TUIC v5 | sing-box | UDP 8443 |
| AnyTLS | sing-box | TCP 2053 |
| Shadowsocks 2022 | sing-box | TCP+UDP 8388 |
| OpenSSH / Dropbear | - | 22 / 109, 143 |
| SSH-SSL (stunnel) | - | 447 → dropbear, 777 → openssh |
| SSH-WebSocket | python | 80, 443 (çdo path me `Upgrade: websocket`), 8880 direkt |
| badvpn-udpgw | - | 127.0.0.1:7300 |
| WireGuard | kernel | UDP 51820 |
| OpenVPN (auth me SSH user/pass) | - | TCP 1194, UDP 1195 |

## Instalimi

1. Krijo një rekord **A** për domain-in, p.sh. `vpn.domaini.com → IP e VPS`. Përdor vetëm DNS, pa proxy-n portokalli të Cloudflare.
2. Hap portat më sipër në firewall-in e cloud-it (AWS Security Group, Oracle, GCP...).
3. Në VPS, si `root`:

```bash
apt-get update && apt-get install -y git
git clone https://github.com/agjetaj/vpskit.git && cd vpskit
bash install.sh
```

Pa pyetje (automatikisht):

```bash
DOMAIN=vpn.domaini.com REALITY_SNI=www.microsoft.com HY2_HOP=on bash install.sh -y
```

## Përdorimi

Shkruaj `menu` për menunë, ose përdor komandat direkt:

```text
vpskit add proxy ana 30          # 1 user = të gjitha protokollet proxy + subscription
vpskit add ssh bob 30 Pass123     # SSH + Dropbear + SSL + WS + OpenVPN
vpskit add wg tel 30              # WireGuard + QR
vpskit trial proxy 2              # user provë për 2 orë
vpskit show ana | renew ana 30 | del ana | list
vpskit traffic | online | status | restart
vpskit hop on|off                 # Hysteria2 port hopping
vpskit domain domain.i.ri         # certifikatë e re + rigjenerim i konfigurimeve
vpskit update                     # Xray + sing-box në versionin më të fundit
vpskit backup | restore /root/vpskit-backup-....tar.gz
```

Çdo përdorues proxy merr:
- linke `vless://`, `vmess://`, `trojan://`, `hysteria2://`, `tuic://`, `anytls://`, `ss://`
- **subscription** `https://DOMAIN/sub/<token>` për v2rayN, v2rayNG, Hiddify, NekoBox, Streisand
- **Clash Meta / mihomo** `https://DOMAIN/sub/<token>.yaml` me grup AUTO (url-test)
- kod QR në terminal

Përdoruesit e skaduar fshihen automatikisht çdo 5 minuta (`vpskit-expire.timer`).

## Veçoritë kryesore

- **Xray-core + sing-box** në versionin më të fundit (shkarkohen nga GitHub releases, `vpskit update`).
- **Reality** (pa certifikatë, i vështirë për t'u dalluar), **XHTTP**, **Hysteria2**, **TUIC**, **AnyTLS**, **SS-2022**.
- Një bazë e vetme përdoruesish (`/etc/vpskit/users.json`). Konfigurimet rigjenerohen dhe testohen (`xray -test`, `sing-box check`) para çdo restart-i.
- Çdo shërbim ka unit-in e vet systemd (`vpskit-*`), pavarësisht nga ndryshimet e paketave në Debian 13 / Ubuntu 24.04+.
- Certifikata vjen nga Let's Encrypt me `acme.sh` dhe rinovohet automatikisht.
- Përdoret `sysctl.d` (Debian 13 nuk lexon më `/etc/sysctl.conf`), `http2 on;` për nginx ≥ 1.25 dhe flag për CMake 4 (badvpn në Ubuntu 25.10+).
- Fjalëkalimet SSH ruhen vetëm si hash. Backup-i i rikrijon përdoruesit.

## Skedarët

```text
install.sh          instaluesi
bin/vpskit          menu + CLI  (/usr/local/bin/vpskit, /usr/local/bin/menu)
bin/ws-proxy.py     SSH-WebSocket proxy
lib/common.sh       portat, helper-at, baza e përdoruesve
lib/system.sh       OS, kernel/BBR, nginx, TLS, NAT, timer
lib/proxy.sh        Xray + sing-box, linke, subscription
lib/ssh.sh          dropbear, stunnel, ssh-ws, badvpn, user SSH
lib/vpn.sh          WireGuard, OpenVPN
```

Përdore vetëm në serverat e tu dhe në përputhje me ligjet e vendit ku ndodhesh.
