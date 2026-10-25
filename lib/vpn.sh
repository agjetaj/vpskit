#!/usr/bin/env bash
# vpskit - WireGuard + OpenVPN (OpenVPN authenticates with the SSH accounts via PAM)

WG_NET="10.66.66"
WG_DIR="/etc/wireguard"
OVPN_DIR="/etc/openvpn/server"

# ---------------- WireGuard ----------------
install_wireguard() {
  info "Installing WireGuard..."
  apt-get install -y wireguard-tools qrencode >/dev/null || die "apt install failed (wireguard)"
  mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"
  if [[ ! -f $WG_DIR/server.key ]]; then
    (umask 077; wg genkey > "$WG_DIR/server.key")
    wg pubkey < "$WG_DIR/server.key" > "$WG_DIR/server.pub"
  fi
  render_wg
  systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || warn "wg-quick@wg0 failed to start (kernel module?)"
  ok "WireGuard on UDP $P_WG"
}

render_wg() {
  {
    echo "[Interface]"
    echo "Address = $WG_NET.1/24"
    echo "ListenPort = $P_WG"
    echo "PrivateKey = $(cat "$WG_DIR/server.key")"
    jq -r '.[] | select(.type=="wg") | "\n# \(.name)\n[Peer]\nPublicKey = \(.pub)\nPresharedKey = \(.psk)\nAllowedIPs = \(.ip)/32"' "$DB"
  } > "$WG_DIR/wg0.conf"
  chmod 600 "$WG_DIR/wg0.conf"
  if ip link show wg0 &>/dev/null; then
    wg syncconf wg0 <(wg-quick strip wg0)
  fi
}

wg_free_ip() {
  local i used; used=$(jq -r '.[] | select(.type=="wg") | .ip' "$DB")
  for i in $(seq 2 254); do
    grep -qx "$WG_NET.$i" <<<"$used" || { echo "$WG_NET.$i"; return; }
  done
  die "WireGuard subnet is full."
}

wg_add() { # wg_add NAME EXPIRY_EPOCH
  local n=$1 exp=$2 priv pub psk ip
  priv=$(wg genkey); pub=$(wg pubkey <<<"$priv"); psk=$(wg genpsk); ip=$(wg_free_ip)
  db_add "$(jq -cn --arg n "$n" --arg pr "$priv" --arg pu "$pub" --arg ps "$psk" --arg ip "$ip" \
    --argjson e "$exp" --argjson c "$(now)" \
    '{name:$n, type:"wg", priv:$pr, pub:$pu, psk:$ps, ip:$ip, created:$c, expiry:$e}')"
  render_wg
}

wg_client_conf() {
  load_conf
  local n=$1
  cat <<EOF
[Interface]
PrivateKey = $(db_field "$n" priv)
Address = $(db_field "$n" ip)/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $(cat "$WG_DIR/server.pub")
PresharedKey = $(db_field "$n" psk)
Endpoint = $IP:$P_WG
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
}

# ---------------- OpenVPN ----------------
install_openvpn() {
  info "Installing OpenVPN..."
  apt-get install -y openvpn easy-rsa >/dev/null || die "apt install failed (openvpn)"
  mkdir -p "$OVPN_DIR"
  local ers="$OVPN_DIR/easy-rsa"
  if [[ ! -f $ers/pki/issued/server.crt ]]; then
    rm -rf "$ers"; mkdir -p "$ers"; cp -r /usr/share/easy-rsa/* "$ers/"
    (
      cd "$ers" || exit 1
      export EASYRSA_BATCH=1 EASYRSA_REQ_CN="vpskit-ca" EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1 \
             EASYRSA_CA_EXPIRE=3650 EASYRSA_CERT_EXPIRE=3650
      ./easyrsa init-pki >/dev/null 2>&1
      ./easyrsa build-ca nopass >/dev/null 2>&1
      ./easyrsa build-server-full server nopass >/dev/null 2>&1
    ) || die "easy-rsa failed"
    cp "$ers/pki/ca.crt" "$ers/pki/issued/server.crt" "$ers/pki/private/server.key" "$OVPN_DIR/"
    openvpn --genkey secret "$OVPN_DIR/tc.key"
  fi

  # PAM service: plain unix auth + account expiry check
  cat > /etc/pam.d/openvpn <<'EOF'
auth    required pam_unix.so
account required pam_unix.so
EOF
  local plugin
  plugin=$(find /usr/lib -name 'openvpn-plugin-auth-pam.so' 2>/dev/null | head -1)
  [[ -n $plugin ]] || die "openvpn-plugin-auth-pam.so not found"

  local proto port net
  for proto in tcp udp; do
    if [[ $proto == tcp ]]; then port=$P_OVPN_TCP; net=10.8.0.0; else port=$P_OVPN_UDP; net=10.9.0.0; fi
    cat > "$OVPN_DIR/$proto.conf" <<EOF
port $port
proto $proto
dev tun
ca $OVPN_DIR/ca.crt
cert $OVPN_DIR/server.crt
key $OVPN_DIR/server.key
dh none
tls-crypt $OVPN_DIR/tc.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
topology subnet
server $net 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
plugin $plugin openvpn
verify-client-cert none
username-as-common-name
duplicate-cn
user nobody
group nogroup
persist-key
persist-tun
verb 3
EOF
    [[ $proto == udp ]] && echo "explicit-exit-notify 1" >> "$OVPN_DIR/$proto.conf"
    systemctl enable --now "openvpn-server@$proto" >/dev/null 2>&1 || warn "openvpn-server@$proto failed"
  done
  write_ovpn_clients
  ok "OpenVPN on TCP $P_OVPN_TCP / UDP $P_OVPN_UDP"
}

write_ovpn_clients() {
  load_conf
  mkdir -p "$DL_DIR"
  local proto port
  for proto in tcp udp; do
    [[ $proto == tcp ]] && port=$P_OVPN_TCP || port=$P_OVPN_UDP
    cat > "$DL_DIR/vpskit-$proto.ovpn" <<EOF
client
dev tun
proto $proto
remote $IP $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth-nocache
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verb 3
<ca>
$(cat "$OVPN_DIR/ca.crt")
</ca>
<tls-crypt>
$(cat "$OVPN_DIR/tc.key")
</tls-crypt>
EOF
  done
}
