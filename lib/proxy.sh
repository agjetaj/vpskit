#!/usr/bin/env bash
# vpskit - Xray (VLESS/VMess/Trojan/Reality/XHTTP) + sing-box (Hysteria2/TUIC/AnyTLS/SS-2022)

XRAY_CONF="$ETC/xray.json"
SB_CONF="$ETC/sing-box.json"
SS_METHOD="2022-blake3-aes-128-gcm"

arch_xray() { case $(uname -m) in x86_64) echo 64;; aarch64) echo arm64-v8a;; *) die "Unsupported arch $(uname -m)";; esac; }
arch_sb()   { case $(uname -m) in x86_64) echo amd64;; aarch64) echo arm64;; *) die "Unsupported arch $(uname -m)";; esac; }

install_xray() {
  info "Installing Xray-core (latest)..."
  local tmp; tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/x.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$(arch_xray).zip" \
    || die "Xray download failed"
  unzip -qo "$tmp/x.zip" -d "$tmp/x"
  install -m 755 "$tmp/x/xray" /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  cp "$tmp"/x/geo*.dat /usr/local/share/xray/
  rm -rf "$tmp"

  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray (vpskit)
After=network-online.target

[Service]
User=nobody
Group=nogroup
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=/usr/local/bin/xray run -config $XRAY_CONF
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  ok "Xray $(xray version | head -1 | awk '{print $2}')"
}

install_singbox() {
  info "Installing sing-box (latest)..."
  local ver tmp a
  ver=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name) \
    || die "Cannot query sing-box release"
  ver=${ver#v}; a=$(arch_sb); tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/sb.tgz" \
    "https://github.com/SagerNet/sing-box/releases/download/v$ver/sing-box-$ver-linux-$a.tar.gz" || die "sing-box download failed"
  tar -xzf "$tmp/sb.tgz" -C "$tmp"
  install -m 755 "$tmp/sing-box-$ver-linux-$a/sing-box" /usr/local/bin/sing-box
  rm -rf "$tmp"

  # Runs as root because it reads the TLS key and binds UDP 443.
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box (vpskit)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c $SB_CONF
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  ok "sing-box $ver"
}

# One-time secrets for Reality and Shadowsocks-2022 (stored in vpskit.conf)
init_proxy_keys() {
  local out
  out=$(xray x25519)
  # Old xray prints "Private key:/Public key:", new prints "PrivateKey:/Password:"
  set_conf REALITY_PRIV "$(awk -F': *' '/Private/{print $2; exit}' <<<"$out")"
  set_conf REALITY_PUB  "$(awk -F': *' '/Public|Password/{print $2; exit}' <<<"$out")"
  set_conf REALITY_SID  "$(rand_hex 8)"
  set_conf SS_SERVER_KEY "$(rand_b64 16)"
}

render_xray() {
  load_conf
  local users; users=$(jq -c '[.[] | select(.type=="proxy")]' "$DB")
  jq -n --argjson u "$users" \
    --arg priv "$REALITY_PRIV" --arg sni "$REALITY_SNI" --arg sid "$REALITY_SID" \
    --argjson pr "$P_REALITY" --argjson pvl "$I_VLESS_WS" --argjson pvm "$I_VMESS_WS" \
    --argjson ptr "$I_TROJAN_WS" --argjson pxh "$I_XHTTP" --argjson papi "$I_XRAY_API" '
  def ws($p): {network:"ws", wsSettings:{path:$p}};
  def sniff: {enabled:true, destOverride:["http","tls","quic"]};
  {
    log: {loglevel:"warning", access:"none"},
    api: {tag:"api", listen:("127.0.0.1:"+($papi|tostring)), services:["StatsService"]},
    stats: {},
    policy: {levels:{"0":{statsUserUplink:true, statsUserDownlink:true}}},
    inbounds: [
      {tag:"vless-reality", listen:"0.0.0.0", port:$pr, protocol:"vless",
       settings:{decryption:"none", clients:[$u[] | {id:.uuid, email:.name, flow:"xtls-rprx-vision"}]},
       streamSettings:{network:"raw", security:"reality",
         realitySettings:{dest:($sni+":443"), serverNames:[$sni], privateKey:$priv, shortIds:[$sid]}},
       sniffing:sniff},
      {tag:"vless-ws", listen:"127.0.0.1", port:$pvl, protocol:"vless",
       settings:{decryption:"none", clients:[$u[] | {id:.uuid, email:.name}]},
       streamSettings:ws("/vless"), sniffing:sniff},
      {tag:"vmess-ws", listen:"127.0.0.1", port:$pvm, protocol:"vmess",
       settings:{clients:[$u[] | {id:.uuid, email:.name}]},
       streamSettings:ws("/vmess"), sniffing:sniff},
      {tag:"trojan-ws", listen:"127.0.0.1", port:$ptr, protocol:"trojan",
       settings:{clients:[$u[] | {password:.pass, email:.name}]},
       streamSettings:ws("/trojan"), sniffing:sniff},
      {tag:"vless-xhttp", listen:"127.0.0.1", port:$pxh, protocol:"vless",
       settings:{decryption:"none", clients:[$u[] | {id:.uuid, email:.name}]},
       streamSettings:{network:"xhttp", xhttpSettings:{path:"/xhttp", mode:"auto"}}, sniffing:sniff}
    ],
    outbounds: [{protocol:"freedom", tag:"direct"}, {protocol:"blackhole", tag:"block"}],
    routing: {rules: [
      {type:"field", ip:["geoip:private"], outboundTag:"block"},
      {type:"field", protocol:["bittorrent"], outboundTag:"block"}
    ]}
  }' > "$XRAY_CONF.tmp" || die "render_xray failed"
  mv "$XRAY_CONF.tmp" "$XRAY_CONF"
  chown root:nogroup "$XRAY_CONF"; chmod 640 "$XRAY_CONF"
}

render_singbox() {
  load_conf
  local users listen="0.0.0.0"
  users=$(jq -c '[.[] | select(.type=="proxy")]' "$DB")
  [[ -f /proc/net/if_inet6 ]] && listen="::"
  jq -n --argjson u "$users" --arg l "$listen" \
    --arg crt "$TLS_DIR/fullchain.pem" --arg key "$TLS_DIR/key.pem" --arg dom "$DOMAIN" \
    --arg ssm "$SS_METHOD" --arg ssk "$SS_SERVER_KEY" --arg site "$WWW/site" \
    --argjson phy "$P_HTTPS" --argjson ptu "$P_TUIC" --argjson pat "$P_ANYTLS" --argjson pss "$P_SS" '
  def tls($alpn): {enabled:true, server_name:$dom, alpn:$alpn, certificate_path:$crt, key_path:$key};
  {
    log: {level:"warn"},
    inbounds: [
      {type:"hysteria2", tag:"hy2", listen:$l, listen_port:$phy,
       users:[$u[] | {name, password:.pass}],
       masquerade:("file://"+$site), tls:tls(["h3"])},
      {type:"tuic", tag:"tuic", listen:$l, listen_port:$ptu,
       users:[$u[] | {name, uuid, password:.pass}],
       congestion_control:"bbr", tls:tls(["h3"])},
      {type:"anytls", tag:"anytls", listen:$l, listen_port:$pat,
       users:[$u[] | {name, password:.pass}], tls:tls(["h2","http/1.1"])},
      {type:"shadowsocks", tag:"ss2022", listen:$l, listen_port:$pss,
       method:$ssm, password:$ssk, users:[$u[] | {name, password:.ss_key}]}
    ],
    outbounds: [{type:"direct", tag:"direct"}]
  }' > "$SB_CONF.tmp" || die "render_singbox failed"
  mv "$SB_CONF.tmp" "$SB_CONF"; chmod 600 "$SB_CONF"
}

apply_proxy() {
  render_xray; render_singbox
  if ! xray run -test -config "$XRAY_CONF" >/dev/null 2>&1; then
    xray run -test -config "$XRAY_CONF"; die "Xray config test failed"
  fi
  sing-box check -c "$SB_CONF" || die "sing-box config test failed"
  systemctl restart xray sing-box
}

# ---- client links / subscription ----
proxy_links() { # proxy_links NAME
  load_conf
  local n=$1 uuid pass ssk d=$DOMAIN e vm
  uuid=$(db_field "$n" uuid); pass=$(db_field "$n" pass); ssk=$(db_field "$n" ss_key)
  e=$(urlenc "$n")
  echo "vless://$uuid@$IP:$P_REALITY?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$REALITY_PUB&sid=$REALITY_SID&type=tcp#$e-reality"
  echo "vless://$uuid@$d:$P_HTTPS?encryption=none&security=tls&sni=$d&alpn=h2&fp=chrome&type=xhttp&path=%2Fxhttp&mode=auto#$e-xhttp"
  echo "vless://$uuid@$d:$P_HTTPS?encryption=none&security=tls&sni=$d&fp=chrome&type=ws&host=$d&path=%2Fvless#$e-vless-ws"
  vm=$(jq -cn --arg n "$n-vmess-ws" --arg d "$d" --arg id "$uuid" --arg p "$P_HTTPS" \
    '{v:"2",ps:$n,add:$d,port:$p,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$d,path:"/vmess",tls:"tls",sni:$d,fp:"chrome"}')
  echo "vmess://$(echo -n "$vm" | base64 -w0)"
  echo "trojan://$(urlenc "$pass")@$d:$P_HTTPS?security=tls&sni=$d&fp=chrome&type=ws&host=$d&path=%2Ftrojan#$e-trojan-ws"
  local hop=""; [[ ${HY2_HOP:-off} == on ]] && hop="&mport=${P_HY2_HOP/:/-}"
  echo "hysteria2://$(urlenc "$pass")@$d:$P_HTTPS?sni=$d&alpn=h3$hop#$e-hy2"
  echo "tuic://$uuid:$(urlenc "$pass")@$d:$P_TUIC?sni=$d&alpn=h3&congestion_control=bbr&udp_relay_mode=native#$e-tuic"
  echo "anytls://$(urlenc "$pass")@$d:$P_ANYTLS?sni=$d#$e-anytls"
  echo "ss://$(echo -n "$SS_METHOD:$SS_SERVER_KEY:$ssk" | base64 -w0)@$IP:$P_SS#$e-ss2022"
}

# Writes https://DOMAIN/sub/<token> (base64 links) and <token>.yaml (Clash Meta / mihomo)
write_subscription() {
  load_conf
  local n=$1 tok uuid pass ssk d=$DOMAIN ports=""
  tok=$(db_field "$n" token); uuid=$(db_field "$n" uuid); pass=$(db_field "$n" pass); ssk=$(db_field "$n" ss_key)
  [[ -n $tok ]] || return 0
  [[ ${HY2_HOP:-off} == on ]] && ports=", ports: ${P_HY2_HOP/:/-}"
  mkdir -p "$WWW/sub"
  proxy_links "$n" | base64 -w0 > "$WWW/sub/$tok"
  cat > "$WWW/sub/$tok.yaml" <<EOF
mixed-port: 7890
mode: rule
log-level: warning
proxies:
  - {name: $n-reality, type: vless, server: $IP, port: $P_REALITY, uuid: $uuid, network: tcp, tls: true, udp: true, flow: xtls-rprx-vision, servername: $REALITY_SNI, client-fingerprint: chrome, reality-opts: {public-key: $REALITY_PUB, short-id: $REALITY_SID}}
  - {name: $n-hy2, type: hysteria2, server: $d, port: $P_HTTPS, password: "$pass", sni: $d, alpn: [h3]$ports}
  - {name: $n-tuic, type: tuic, server: $d, port: $P_TUIC, uuid: $uuid, password: "$pass", sni: $d, alpn: [h3], congestion-controller: bbr, udp-relay-mode: native}
  - {name: $n-anytls, type: anytls, server: $d, port: $P_ANYTLS, password: "$pass", sni: $d, client-fingerprint: chrome, udp: true}
  - {name: $n-vless-ws, type: vless, server: $d, port: $P_HTTPS, uuid: $uuid, tls: true, udp: true, servername: $d, network: ws, ws-opts: {path: /vless, headers: {Host: $d}}}
  - {name: $n-vmess-ws, type: vmess, server: $d, port: $P_HTTPS, uuid: $uuid, alterId: 0, cipher: auto, tls: true, udp: true, servername: $d, network: ws, ws-opts: {path: /vmess, headers: {Host: $d}}}
  - {name: $n-trojan-ws, type: trojan, server: $d, port: $P_HTTPS, password: "$pass", sni: $d, udp: true, network: ws, ws-opts: {path: /trojan, headers: {Host: $d}}}
  - {name: $n-ss2022, type: ss, server: $IP, port: $P_SS, cipher: $SS_METHOD, password: "$SS_SERVER_KEY:$ssk", udp: true}
proxy-groups:
  - {name: PROXY, type: select, proxies: [AUTO, $n-reality, $n-hy2, $n-tuic, $n-anytls, $n-vless-ws, $n-vmess-ws, $n-trojan-ws, $n-ss2022]}
  - {name: AUTO, type: url-test, url: "https://www.gstatic.com/generate_204", interval: 300, proxies: [$n-reality, $n-hy2, $n-tuic, $n-anytls]}
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - MATCH,PROXY
EOF
}

# Per-user traffic from Xray stats (sing-box release builds have no stats API)
xray_traffic() {
  load_conf
  xray api statsquery --server="127.0.0.1:$I_XRAY_API" -pattern 'user>>>' 2>/dev/null |
    jq -r '[.stat[]? | {u:(.name|split(">>>")[1]), v:(.value|tonumber)}]
           | group_by(.u)[] | "\(.[0].u)\t\((map(.v)|add)/1048576*100|floor/100) MiB"'
}
