#!/usr/bin/env bash
# vpskit installer - Debian 11/12/13, Ubuntu 22.04/24.04/25.04/25.10/26.04 (amd64/arm64)
#
#   bash install.sh
# Non-interactive:
#   DOMAIN=vpn.example.com REALITY_SNI=www.microsoft.com HY2_HOP=on bash install.sh -y

SRC=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
source "$SRC/lib/common.sh"
need_root

for f in system proxy ssh vpn; do
  # shellcheck disable=SC1090
  source "$SRC/lib/$f.sh"
done

AUTO=0; [[ $1 == -y ]] && AUTO=1
prompt() { # prompt VAR "question" default
  local var=$1 q=$2 def=$3 v
  if [[ -n ${!var} ]]; then return; fi
  if (( AUTO )); then printf -v "$var" '%s' "$def"; return; fi
  read -rp "$q [$def]: " v
  printf -v "$var" '%s' "${v:-$def}"
}

clear
echo "================ vpskit installer ================"
check_os
install_base

IP=$(public_ip)
[[ -n $IP ]] || die "Cannot detect public IPv4."
prompt DOMAIN "Domain pointing to $IP (A record, DNS only)" ""
[[ -n $DOMAIN ]] || die "A domain is required (TLS for XHTTP/WS/Hysteria2/TUIC/AnyTLS)."
prompt REALITY_SNI "Reality target site (TLS1.3 + H2)" "www.microsoft.com"
prompt HY2_HOP "Hysteria2 port hopping UDP ${P_HY2_HOP/:/-} (on/off)" "on"
prompt ACME_EMAIL "E-mail for Let's Encrypt (optional)" ""

resolved=$(getent ahostsv4 "$DOMAIN" | awk '{print $1; exit}')
[[ $resolved == "$IP" ]] || warn "$DOMAIN resolves to '${resolved:-nothing}', not $IP. The certificate step will fail if DNS is wrong."

# ---- files ----
mkdir -p "$VPSKIT_DIR" "$ETC" "$TLS_DIR"; chmod 700 "$ETC"
cp -r "$SRC/lib" "$SRC/bin" "$VPSKIT_DIR/"
install -m 755 "$SRC/bin/vpskit" /usr/local/bin/vpskit
ln -sf /usr/local/bin/vpskit /usr/local/bin/menu

set_conf DOMAIN "$DOMAIN"
set_conf IP "$IP"
set_conf REALITY_SNI "$REALITY_SNI"
set_conf HY2_HOP "$HY2_HOP"
set_conf ACME_EMAIL "$ACME_EMAIL"
chmod 600 "$CONF"
db_init

tune_kernel

# ---- proxy cores ----
install_xray
install_singbox
load_conf
[[ -n ${REALITY_PRIV:-} ]] || init_proxy_keys

# Hidden internal user so no inbound ever has an empty user list
if ! db_has _sys; then
  db_add "$(jq -cn --arg u "$(new_uuid)" --arg p "$(rand_pass 24)" --arg s "$(rand_b64 16)" \
    '{name:"_sys", type:"proxy", uuid:$u, pass:$p, ss_key:$s, token:"", created:0, expiry:4102444800}')"
fi

# ---- web + TLS ----
write_site
issue_cert
write_nginx
systemctl enable nginx >/dev/null 2>&1
systemctl restart nginx || die "nginx failed to start"

# ---- legacy stack ----
install_ssh_stack
systemctl restart vpskit-stunnel || warn "stunnel failed to start"
install_wireguard
install_openvpn

write_firewall
install_timer

systemctl daemon-reload
systemctl enable xray sing-box >/dev/null 2>&1
apply_proxy

echo
ok "Installation finished."
vpskit status
cat <<EOF

  Menu:              menu   (or: vpskit)
  Create a user:     vpskit add proxy NAME 30
                     vpskit add ssh NAME 30 PASSWORD
                     vpskit add wg NAME 30

  Open these ports in your cloud firewall / security group (AWS, GCP, Oracle...):
    TCP: 22 80 443 $P_REALITY $P_ANYTLS $P_SS 109 143 $P_STUNNEL $P_STUNNEL2 $P_SSHWS $P_OVPN_TCP
    UDP: 443 $P_TUIC $P_SS $P_WG $P_OVPN_UDP $( [[ $HY2_HOP == on ]] && echo "${P_HY2_HOP/:/-}")
EOF
