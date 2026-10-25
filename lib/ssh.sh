#!/usr/bin/env bash
# vpskit - SSH stack: Dropbear, stunnel (SSL), SSH-WebSocket proxy, badvpn-udpgw
#
# Every daemon gets its own systemd unit so we never depend on distro defaults
# (/etc/default/dropbear, stunnel4 init scripts, ...) which differ between
# Debian 11-13 and Ubuntu 22.04-26.04.

install_ssh_stack() {
  info "Installing Dropbear, stunnel, SSH-WS..."
  apt-get install -y dropbear-bin stunnel4 python3 >/dev/null || die "apt install failed (ssh stack)"
  # distro units would clash on ports - we run our own
  systemctl disable --now dropbear stunnel4 2>/dev/null || true

  # Shell-less accounts must have their shell listed for dropbear/sshd to accept them
  local sh
  for sh in /bin/false /usr/bin/false /usr/sbin/nologin; do
    grep -qx "$sh" /etc/shells || echo "$sh" >> /etc/shells
  done

  mkdir -p "$ETC/dropbear"
  local t
  for t in ed25519 ecdsa rsa; do
    [[ -f $ETC/dropbear/$t ]] || dropbearkey -t "$t" -f "$ETC/dropbear/$t" >/dev/null 2>&1
  done
  cat > "$ETC/dropbear/banner" <<'EOF'
<font color="#16a34a"><b>vpskit server</b></font>
EOF

  cat > /etc/systemd/system/vpskit-dropbear.service <<EOF
[Unit]
Description=Dropbear SSH (vpskit)
After=network.target

[Service]
ExecStart=/usr/sbin/dropbear -F -E -p $P_DROPBEAR -p $P_DROPBEAR2 -W 65536 -b $ETC/dropbear/banner \
  -r $ETC/dropbear/ed25519 -r $ETC/dropbear/ecdsa -r $ETC/dropbear/rsa
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  local stunnel_bin; stunnel_bin=$(command -v stunnel4 || command -v stunnel)
  cat > "$ETC/stunnel.conf" <<EOF
foreground = yes
pid =
cert = $TLS_DIR/fullchain.pem
key = $TLS_DIR/key.pem
sslVersionMin = TLSv1.2

[dropbear]
accept = $P_STUNNEL
connect = 127.0.0.1:$P_DROPBEAR

[openssh]
accept = $P_STUNNEL2
connect = 127.0.0.1:$P_SSH
EOF
  cat > /etc/systemd/system/vpskit-stunnel.service <<EOF
[Unit]
Description=stunnel SSH-SSL (vpskit)
After=network.target

[Service]
ExecStart=$stunnel_bin $ETC/stunnel.conf
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  install -m 755 "$VPSKIT_DIR/bin/ws-proxy.py" /usr/local/bin/vpskit-ws-proxy
  cat > /etc/systemd/system/vpskit-sshws.service <<EOF
[Unit]
Description=SSH over WebSocket proxy (vpskit)
After=network.target

[Service]
User=nobody
ExecStart=/usr/bin/python3 /usr/local/bin/vpskit-ws-proxy $P_SSHWS $P_DROPBEAR
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  install_badvpn
  systemctl daemon-reload
  systemctl enable --now vpskit-dropbear vpskit-sshws >/dev/null 2>&1
  systemctl enable vpskit-stunnel >/dev/null 2>&1   # started once the certificate exists
  ok "SSH stack ready"
}

install_badvpn() {
  [[ -x /usr/local/bin/badvpn-udpgw ]] && return
  info "Building badvpn-udpgw..."
  apt-get install -y cmake build-essential git >/dev/null || { warn "badvpn deps missing, skipped"; return; }
  local tmp; tmp=$(mktemp -d)
  git clone -q --depth 1 https://github.com/ambrop72/badvpn.git "$tmp/badvpn" || { warn "badvpn clone failed, skipped"; return; }
  # CMAKE_POLICY_VERSION_MINIMUM: CMake 4 (Ubuntu 25.10+/26.04) refuses badvpn's old cmake_minimum_required
  if cmake -S "$tmp/badvpn" -B "$tmp/build" -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null &&
     cmake --build "$tmp/build" -j"$(nproc)" >/dev/null; then
    install -m 755 "$tmp/build/udpgw/badvpn-udpgw" /usr/local/bin/badvpn-udpgw
  else
    warn "badvpn build failed, skipped"; rm -rf "$tmp"; return
  fi
  rm -rf "$tmp"
  cat > /etc/systemd/system/vpskit-udpgw.service <<EOF
[Unit]
Description=badvpn-udpgw (vpskit)
After=network.target

[Service]
User=nobody
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$P_UDPGW --max-clients 1000 --max-connections-for-client 20
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpskit-udpgw >/dev/null 2>&1
}

# ---- SSH accounts (also used by OpenVPN through PAM) ----
ssh_add() { # ssh_add NAME PASS EXPIRY_EPOCH
  local n=$1 p=$2 exp=$3 hash
  id "$n" &>/dev/null && die "System user '$n' already exists."
  useradd -M -s /bin/false -e "$(date -d "@$exp" +%Y-%m-%d)" "$n"
  echo "$n:$p" | chpasswd
  hash=$(getent shadow "$n" | cut -d: -f2)
  db_add "$(jq -cn --arg n "$n" --arg h "$hash" --argjson e "$exp" --argjson c "$(now)" \
    '{name:$n, type:"ssh", hash:$h, created:$c, expiry:$e}')"
}

ssh_del() { pkill -KILL -u "$1" 2>/dev/null; userdel -f "$1" 2>/dev/null; db_del "$1"; }

ssh_renew() { usermod -e "$(date -d "@$2" +%Y-%m-%d)" "$1"; db_set "$1" expiry "$2"; }

# restore accounts from DB (after backup restore)
ssh_restore_all() {
  jq -r '.[] | select(.type=="ssh") | [.name, .hash, .expiry] | @tsv' "$DB" |
  while IFS=$'\t' read -r n h e; do
    id "$n" &>/dev/null || useradd -M -s /bin/false -p "$h" -e "$(date -d "@$e" +%Y-%m-%d)" "$n"
  done
}

ssh_online() {
  echo "Active SSH/Dropbear sessions per user:"
  ps -eo user=,comm= | awk '$2 ~ /^(sshd|dropbear)$/ && $1 != "root" {c[$1]++} END {for (u in c) printf "  %-20s %d\n", u, c[u]}'
}
