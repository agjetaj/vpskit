#!/usr/bin/env bash
# vpskit - common helpers (paths, output, config, user database)

VPSKIT_DIR="/opt/vpskit"
ETC="/etc/vpskit"
CONF="$ETC/vpskit.conf"
DB="$ETC/users.json"
TLS_DIR="$ETC/tls"
WWW="/var/www/vpskit"
DL_DIR="$WWW/dl"

# ---- Ports (one place to change them) ----
P_HTTP=80            # nginx: SSH-WS / VLESS-WS / VMess-WS / Trojan-WS (no TLS)
P_HTTPS=443          # nginx TLS: same paths + XHTTP; UDP 443 = Hysteria2
P_REALITY=8443       # Xray VLESS + Reality + Vision (TCP)
P_TUIC=8443          # sing-box TUIC v5 (UDP)
P_ANYTLS=2053        # sing-box AnyTLS (TCP)
P_SS=8388            # sing-box Shadowsocks-2022 (TCP+UDP)
P_SSH=22
P_DROPBEAR=109
P_DROPBEAR2=143
P_STUNNEL=447        # stunnel -> dropbear
P_STUNNEL2=777       # stunnel -> openssh
P_SSHWS=8880         # python SSH-WS proxy (direct, any payload)
P_UDPGW=7300         # badvpn-udpgw (localhost)
P_WG=51820
P_OVPN_TCP=1194
P_OVPN_UDP=1195
P_HY2_HOP="20000:40000"

# internal ports (127.0.0.1 only)
I_VLESS_WS=10001
I_VMESS_WS=10002
I_TROJAN_WS=10003
I_XHTTP=10004
I_XRAY_API=10085

C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[0;33m'; C_B='\033[0;36m'; C_0='\033[0m'
info() { echo -e "${C_B}[*]${C_0} $*"; }
ok()   { echo -e "${C_G}[+]${C_0} $*"; }
warn() { echo -e "${C_Y}[!]${C_0} $*"; }
die()  { echo -e "${C_R}[x]${C_0} $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }

load_conf() {
  [[ -f $CONF ]] || die "vpskit is not installed ($CONF missing)."
  # shellcheck disable=SC1090
  source "$CONF"
}

# set_conf KEY VALUE  - create or update a line in vpskit.conf
set_conf() {
  local k=$1 v=$2
  touch "$CONF"
  if grep -q "^$k=" "$CONF"; then
    sed -i "s|^$k=.*|$k=\"$v\"|" "$CONF"
  else
    echo "$k=\"$v\"" >> "$CONF"
  fi
}

rand_hex()  { openssl rand -hex "${1:-8}"; }
rand_pass() { openssl rand -base64 18 | tr -d '/+=' | head -c "${1:-16}"; }
rand_b64()  { openssl rand -base64 "${1:-16}"; }
new_uuid()  { cat /proc/sys/kernel/random/uuid; }
now()       { date +%s; }
fmt_date()  { date -d "@$1" '+%Y-%m-%d %H:%M'; }
urlenc()    { jq -rn --arg s "$1" '$s|@uri'; }

public_ip() {
  curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null ||
  curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null ||
  ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'
}

# ---- user database (JSON array in $DB) ----
db_init()   { [[ -f $DB ]] || echo '[]' > "$DB"; chmod 600 "$DB"; }
db_has()    { jq -e --arg n "$1" 'any(.[]; .name==$n)' "$DB" >/dev/null; }
db_get()    { jq -c --arg n "$1" '.[] | select(.name==$n)' "$DB"; }
db_field()  { jq -r --arg n "$1" --arg f "$2" '.[] | select(.name==$n) | .[$f] // empty' "$DB"; }
db_add()    { local t; t=$(mktemp); jq --argjson u "$1" '. + [$u]' "$DB" > "$t" && mv "$t" "$DB"; chmod 600 "$DB"; }
db_del()    { local t; t=$(mktemp); jq --arg n "$1" 'map(select(.name!=$n))' "$DB" > "$t" && mv "$t" "$DB"; chmod 600 "$DB"; }
db_set()    { # db_set NAME FIELD JSON_VALUE
  local t; t=$(mktemp)
  jq --arg n "$1" --arg f "$2" --argjson v "$3" 'map(if .name==$n then .[$f]=$v else . end)' "$DB" > "$t" && mv "$t" "$DB"
  chmod 600 "$DB"
}

valid_name() { [[ $1 =~ ^[a-z][a-z0-9_-]{2,31}$ ]]; }
