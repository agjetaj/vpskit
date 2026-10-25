#!/usr/bin/env bash
# vpskit - OS checks, packages, kernel tuning, nginx, TLS certificates, firewall/NAT

check_os() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS."
  # shellcheck disable=SC1091
  source /etc/os-release
  local v=${VERSION_ID:-0}
  case $ID in
    debian)
      [[ ${v%%.*} -ge 11 ]] || die "Debian $v is too old (need 11+)."
      [[ ${v%%.*} -gt 13 ]] && warn "Debian $v is newer than tested (11-13), continuing." ;;
    ubuntu)
      dpkg --compare-versions "$v" ge 22.04 || die "Ubuntu $v is too old (need 22.04+)."
      dpkg --compare-versions "$v" gt 26.04 && warn "Ubuntu $v is newer than tested (22.04-26.04), continuing." ;;
    *) die "Unsupported OS: $ID (Debian 11+ / Ubuntu 22.04+ only)." ;;
  esac
  case $(uname -m) in x86_64|aarch64) ;; *) die "Unsupported CPU: $(uname -m)";; esac
  [[ -d /run/systemd/system ]] || die "systemd is required."
  # OpenVZ/LXC without tun cannot run WireGuard/OpenVPN
  [[ -c /dev/net/tun ]] || warn "/dev/net/tun missing: WireGuard/OpenVPN will not work on this VPS."
  ok "OS: $PRETTY_NAME ($(uname -m))"
}

install_base() {
  info "Installing base packages..."
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
  apt-get update -qq || die "apt update failed"
  apt-get install -y curl wget jq unzip tar openssl ca-certificates socat cron iptables \
    iproute2 procps qrencode nginx >/dev/null || die "apt install failed (base)"
  systemctl enable --now cron >/dev/null 2>&1 || true
}

tune_kernel() {
  # /etc/sysctl.d works everywhere; Debian 13 no longer reads /etc/sysctl.conf
  cat > /etc/sysctl.d/99-vpskit.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
EOF
  modprobe tcp_bbr 2>/dev/null || true
  sysctl --system >/dev/null 2>&1
  ok "BBR + IP forwarding enabled ($(sysctl -n net.ipv4.tcp_congestion_control))"
}

# ---------------- nginx ----------------
write_site() {
  mkdir -p "$WWW/site" "$WWW/sub" "$DL_DIR"
  cat > "$WWW/site/index.html" <<'EOF'
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Welcome</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:15vh auto;padding:0 16px;color:#333}</style>
</head><body><h1>It works.</h1><p>This server is running normally.</p></body></html>
EOF
}

write_nginx() {
  load_conf
  local nv h2_listen="" h2_line="" v6=0
  nv=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  # nginx >= 1.25.1 (Debian 13, Ubuntu 24.10+) deprecates "listen ... http2"
  if dpkg --compare-versions "$nv" ge 1.25.1; then h2_line="http2 on;"; else h2_listen=" http2"; fi
  [[ -f /proc/net/if_inet6 ]] && v6=1

  rm -f /etc/nginx/sites-enabled/default
  cat > /etc/nginx/vpskit-ws.inc <<EOF
proxy_http_version 1.1;
proxy_set_header Upgrade \$http_upgrade;
proxy_set_header Connection \$vpskit_conn;
proxy_set_header Host \$host;
proxy_set_header X-Real-IP \$remote_addr;
proxy_read_timeout 1d;
proxy_send_timeout 1d;
proxy_buffering off;
EOF
  cat > /etc/nginx/vpskit-locations.inc <<EOF
location /vless  { proxy_pass http://127.0.0.1:$I_VLESS_WS;  include /etc/nginx/vpskit-ws.inc; }
location /vmess  { proxy_pass http://127.0.0.1:$I_VMESS_WS;  include /etc/nginx/vpskit-ws.inc; }
location /trojan { proxy_pass http://127.0.0.1:$I_TROJAN_WS; include /etc/nginx/vpskit-ws.inc; }
# Any other WebSocket upgrade = SSH-WS (HTTP Injector etc.); plain browsers get the decoy site
location / {
  if (\$http_upgrade !~* "websocket") { return 418; }
  proxy_pass http://127.0.0.1:$P_SSHWS;
  include /etc/nginx/vpskit-ws.inc;
}
error_page 418 = @site;
location @site { root $WWW/site; try_files /index.html =404; }
EOF
  cat > /etc/nginx/conf.d/vpskit.conf <<EOF
map \$http_upgrade \$vpskit_conn { default upgrade; '' close; }

server {
  listen $P_HTTP default_server;
  $( ((v6)) && echo "listen [::]:$P_HTTP default_server;" )
  server_name _;
  include /etc/nginx/vpskit-locations.inc;
}

server {
  listen $P_HTTPS ssl$h2_listen default_server;
  $( ((v6)) && echo "listen [::]:$P_HTTPS ssl$h2_listen default_server;" )
  $h2_line
  server_name $DOMAIN _;
  ssl_certificate     $TLS_DIR/fullchain.pem;
  ssl_certificate_key $TLS_DIR/key.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_cache shared:vpskit:10m;

  include /etc/nginx/vpskit-locations.inc;

  location /xhttp {
    grpc_pass grpc://127.0.0.1:$I_XHTTP;
    grpc_set_header Host \$host;
    grpc_read_timeout 1h;
    grpc_send_timeout 1h;
    grpc_buffer_size 16k;
    client_max_body_size 0;
    client_body_timeout 1h;
  }
  location /sub/ { alias $WWW/sub/; default_type text/plain; add_header Cache-Control no-store; }
  location /dl/  { alias $DL_DIR/;  default_type application/octet-stream; }
}
EOF
  nginx -t 2>/dev/null || { nginx -t; die "nginx config test failed"; }
}

# ---------------- TLS (acme.sh, Let's Encrypt) ----------------
issue_cert() {
  load_conf
  mkdir -p "$TLS_DIR"
  if [[ ! -x ~/.acme.sh/acme.sh ]]; then
    curl -fsSL https://get.acme.sh | sh -s email="${ACME_EMAIL:-}" >/dev/null || die "acme.sh install failed"
  fi
  local acme=~/.acme.sh/acme.sh
  $acme --set-default-ca --server letsencrypt >/dev/null
  info "Requesting certificate for $DOMAIN (port 80 must be reachable)..."
  systemctl stop nginx 2>/dev/null
  if ! $acme --issue --standalone -d "$DOMAIN" --keylength ec-256 --force \
        --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"; then
    systemctl start nginx 2>/dev/null
    die "Certificate failed. Check that $DOMAIN points to $IP (DNS only, no Cloudflare proxy) and port 80 is open."
  fi
  $acme --install-cert -d "$DOMAIN" --ecc \
    --key-file "$TLS_DIR/key.pem" --fullchain-file "$TLS_DIR/fullchain.pem" \
    --reloadcmd "systemctl restart nginx sing-box vpskit-stunnel 2>/dev/null; true" >/dev/null
  chmod 600 "$TLS_DIR/key.pem"
  ok "Certificate installed for $DOMAIN"
}

# ---------------- firewall / NAT (idempotent, re-applied at boot) ----------------
write_firewall() {
  cat > "$VPSKIT_DIR/firewall.sh" <<EOF
#!/usr/bin/env bash
# generated by vpskit - NAT for VPN subnets + Hysteria2 port hopping
source $CONF
IF=\$(ip -4 route show default | awk '{print \$5; exit}')
add() { local t=\$1; shift; iptables -t "\$t" -C "\$@" 2>/dev/null || iptables -t "\$t" -A "\$@"; }
for net in 10.66.66.0/24 10.8.0.0/24 10.9.0.0/24; do
  add nat POSTROUTING -s "\$net" -o "\$IF" -j MASQUERADE
  add filter FORWARD -s "\$net" -j ACCEPT
done
add filter FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
if [[ \${HY2_HOP:-off} == on ]]; then
  add nat PREROUTING -i "\$IF" -p udp --dport $P_HY2_HOP -j REDIRECT --to-ports $P_HTTPS
else
  iptables -t nat -D PREROUTING -i "\$IF" -p udp --dport $P_HY2_HOP -j REDIRECT --to-ports $P_HTTPS 2>/dev/null || true
fi
EOF
  chmod 755 "$VPSKIT_DIR/firewall.sh"
  cat > /etc/systemd/system/vpskit-firewall.service <<EOF
[Unit]
Description=vpskit NAT rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$VPSKIT_DIR/firewall.sh

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable vpskit-firewall >/dev/null 2>&1
  "$VPSKIT_DIR/firewall.sh"
}

# systemd timer instead of cron for expiry (works on minimal images too)
install_timer() {
  cat > /etc/systemd/system/vpskit-expire.service <<'EOF'
[Unit]
Description=vpskit: remove expired users

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpskit expire
EOF
  cat > /etc/systemd/system/vpskit-expire.timer <<'EOF'
[Unit]
Description=vpskit: check expired users every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpskit-expire.timer >/dev/null 2>&1
}
