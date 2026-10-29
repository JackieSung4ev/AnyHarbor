#!/usr/bin/env bash
# Sourced by anytls-manager.sh; never run this module by itself.
# A dedicated nginx process serves only current token-addressed exports.
readonly SUB_SERVICE=jackie-anytls-sub.service SUB_ACCOUNT=jackie-anytls-sub
readonly SUB_UNIT=/etc/systemd/system/jackie-anytls-sub.service
readonly SUB_MARK=jackie-anytls-subscription-v1
readonly SUB_BASE="$BASE/subscription"

subscription_guard_unit() {
    local directory name
    for directory in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        for name in "$SUB_SERVICE.d" jackie-anytls-.service.d jackie-.service.d; do
            [[ ! -e "$directory/$name" && ! -L "$directory/$name" ]] || die "发现订阅服务覆盖目录，停止操作：$directory/$name"
        done
        if [[ "$directory" != /etc/systemd/system ]]; then
            [[ ! -e "$directory/$SUB_SERVICE" && ! -L "$directory/$SUB_SERVICE" ]] || die "发现其他同名订阅服务：$directory/$SUB_SERVICE"
        fi
    done
    if [[ -e "$SUB_UNIT" || -L "$SUB_UNIT" ]]; then
        [[ -f "$SUB_UNIT" && ! -L "$SUB_UNIT" ]] || die '订阅服务文件类型异常。'
        grep -qx "# Managed by $SUB_MARK" "$SUB_UNIT" || die '同名订阅服务不属于本工具，拒绝覆盖。'
        root_readonly "$SUB_UNIT"
    fi
}

subscription_owned() {
    [[ -d "$SUB_BASE" && ! -L "$SUB_BASE" && -f "$SUB_BASE/.owner" && ! -L "$SUB_BASE/.owner" ]] || die '未找到本工具管理的订阅服务目录。'
    root_readonly "$SUB_BASE"
    root_readonly "$SUB_BASE/.owner"
    [[ $(cat "$SUB_BASE/.owner") == "$SUB_MARK" ]] || die '订阅服务归属标记不匹配。'
    root_readonly "$SUB_BASE/releases"
    [[ -f "$SUB_BASE/.user-created" && ! -L "$SUB_BASE/.user-created" ]] || die '订阅服务用户标记缺失。'
    root_readonly "$SUB_BASE/.user-created"
    getent passwd "$SUB_ACCOUNT" >/dev/null || die '订阅服务用户缺失。'
    getent group "$SUB_ACCOUNT" >/dev/null || die '订阅服务用户组缺失。'
}

subscription_initialize() {
    subscription_guard_unit
    if [[ ! -e "$SUB_BASE" && ! -L "$SUB_BASE" ]]; then
        getent passwd "$SUB_ACCOUNT" >/dev/null && die '同名订阅用户已存在，拒绝接管。'
        getent group "$SUB_ACCOUNT" >/dev/null && die '同名订阅用户组已存在，拒绝接管。'
        [[ ! -e "$SUB_UNIT" && ! -L "$SUB_UNIT" ]] || die '订阅服务存在但数据归属标记缺失。'
        install -d -m 0700 "$SUB_BASE" "$SUB_BASE/releases"
        printf '%s\n' "$SUB_MARK" >"$SUB_BASE/.owner"
        useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin "$SUB_ACCOUNT"
        touch "$SUB_BASE/.user-created"
        chown root:"$SUB_ACCOUNT" "$SUB_BASE" "$SUB_BASE/releases"
        chmod 0750 "$SUB_BASE" "$SUB_BASE/releases"
    fi
    subscription_owned
    # The non-root Nginx capability probe runs before publishing a generation.
    # Permit ancestor traversal now; private files and subscription directories
    # retain their own restrictive permissions.
    chmod 0751 "$BASE"
}

subscription_publish_permissions() {
    local generation=$1 file directory
    [[ -d "$SUB_BASE" && -f "$SUB_BASE/.user-created" ]] || return 0
    subscription_owned
    guard_generation "$generation"
    # Only traversal is granted on these ancestors. Private metadata stays 0600.
    chmod 0751 "$BASE" "$BASE/releases" "$generation"
    [[ -d "$generation/subscriptions" && ! -L "$generation/subscriptions" ]] || die '缺少订阅导出目录。'
    root_readonly "$generation/subscriptions"
    chown root:"$SUB_ACCOUNT" "$generation/subscriptions"
    chmod 0750 "$generation/subscriptions"
    for file in "$generation/subscriptions/"*.yaml; do
        [[ -e "$file" ]] || continue
        [[ -f "$file" && ! -L "$file" && $(basename -- "$file") =~ ^[A-Za-z0-9_-]{43}\.yaml$ ]] || die '订阅导出文件不符合预期。'
        root_readonly "$file"
        chown root:"$SUB_ACCOUNT" "$file"
        chmod 0640 "$file"
    done
    # Earlier generations have only Clash exports. Never expose the private
    # group-ID-addressed export directories; only token-addressed files are public.
    for directory in "$generation/subscriptions_v2rayn" "$generation/subscriptions_shadowrocket"; do
        [[ -e "$directory" || -L "$directory" ]] || continue
        [[ -d "$directory" && ! -L "$directory" ]] || die "订阅导出目录异常：$(basename -- "$directory")"
        root_readonly "$directory"
        chown root:"$SUB_ACCOUNT" "$directory"
        chmod 0750 "$directory"
        for file in "$directory/"*.txt; do
            [[ -e "$file" || -L "$file" ]] || continue
            [[ -f "$file" && ! -L "$file" && $(basename -- "$file") =~ ^[A-Za-z0-9_-]{43}\.txt$ ]] || die "订阅导出文件不符合预期：$(basename -- "$directory")"
            root_readonly "$file"
            chown root:"$SUB_ACCOUNT" "$file"
            chmod 0640 "$file"
        done
    done
}

subscription_current_config() {
    local configuration
    subscription_owned
    [[ -L "$SUB_BASE/current" ]] || die '尚未启用在线订阅。'
    configuration=$(readlink -f -- "$SUB_BASE/current")
    [[ $(dirname -- "$configuration") == "$SUB_BASE/releases" && -d "$configuration" ]] || die '订阅配置指针异常。'
    root_readonly "$configuration"
    local file
    for file in nginx.conf server.crt server.key metadata.json; do
        [[ -f "$configuration/$file" ]] || die "订阅配置文件缺失：$file"
        root_readonly "$configuration/$file"
    done
    printf '%s\n' "$configuration"
}

subscription_metadata() {
    python3 - "$1/metadata.json" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    state = json.load(stream)
value = state[sys.argv[2]]
if not isinstance(value, (str, int)):
    raise ValueError('Invalid subscription metadata')
print(value)
PY
}

subscription_validate_certificate() {
    local directory=$1 domain=$2 certificate_public key_public
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || die '缺少系统 CA，请安装 ca-certificates。'
    openssl x509 -in "$directory/server.crt" -checkend 0 -noout >/dev/null || die '订阅证书无效或已过期。'
    certificate_public=$(openssl x509 -in "$directory/server.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
    key_public=$(openssl pkey -in "$directory/server.key" -passin pass: -pubout -outform DER | sha256sum)
    [[ "$certificate_public" == "$key_public" ]] || die '订阅证书与私钥不匹配。'
    if ! openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$directory/server.crt" \
        -purpose sslserver -verify_hostname "$domain" "$directory/server.crt" >"$directory/certificate-check.log" 2>&1; then
        die '订阅证书未通过系统信任链/域名校验。请提供受信任 CA 的完整证书链，不使用跳过证书验证。'
    fi
}

subscription_nginx_lua_path() {
    local directory=$1 nginx=$2
    shift 2
    # Probe the actual binary, without including website config or loading modules.
    # nginx -t skips Lua VM initialization, so it is only a directive capability check.
    cat >"$directory/lua-probe.conf" <<'EOF'
error_log stderr crit;
pid /run/jackie-anytls-sub/lua-probe.pid;
events {}
http { lua_package_path ";;"; }
EOF
    chown root:"$SUB_ACCOUNT" "$directory/lua-probe.conf"
    chmod 0640 "$directory/lua-probe.conf"
    if runuser -u "$SUB_ACCOUNT" -- "$nginx" "$@" -t -q -p "$SUB_BASE/" \
        -c "$directory/lua-probe.conf" >"$directory/lua-probe.log" 2>&1; then
        rm -f -- "$directory/lua-probe.conf" "$directory/lua-probe.log"
        py nginx-lua-path "$nginx"
    elif grep -Fq 'unknown directive "lua_package_path"' "$directory/lua-probe.log"; then
        rm -f -- "$directory/lua-probe.conf" "$directory/lua-probe.log"
    else
        cat "$directory/lua-probe.log" >&2
        die '订阅 Nginx 能力检查失败，运行中的服务未改变。'
    fi
}

subscription_write_config() {
    local directory=$1 domain=$2 port=$3 lua_path=${4:-} lua_directive=''
    if [[ -n "$lua_path" ]]; then
        [[ "$lua_path" =~ ^/[A-Za-z0-9/._-]+$ ]] || die 'Lua 库路径不符合要求。'
        lua_directive="lua_package_path \"$lua_path/?.lua;$lua_path/?/init.lua\";"
    fi
    # Values are validated before interpolation. Only token-addressed exports are public.
    cat >"$directory/nginx.conf" <<EOF
# Managed by $SUB_MARK
# Subscription formats: clash,v2rayn
# Subscription format: shadowrocket
daemon off;
worker_processes 1;
pid /run/jackie-anytls-sub/nginx.pid;
error_log stderr crit;
events { worker_connections 256; }
http {
    $lua_directive
    access_log off;
    log_not_found off;
    server_tokens off;
    default_type application/yaml;
    open_file_cache off;
    etag off;
    if_modified_since off;
    client_max_body_size 1k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 15s;
    keepalive_timeout 10s;
    client_body_temp_path /run/jackie-anytls-sub/body;
    proxy_temp_path /run/jackie-anytls-sub/proxy;
    fastcgi_temp_path /run/jackie-anytls-sub/fastcgi;
    uwsgi_temp_path /run/jackie-anytls-sub/uwsgi;
    scgi_temp_path /run/jackie-anytls-sub/scgi;
    server {
        listen 0.0.0.0:$port ssl;
        server_name $domain;
        ssl_certificate $directory/server.crt;
        ssl_certificate_key $directory/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache off;
        ssl_session_tickets off;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
        location ~ "^/s/(?<subscription_token>[A-Za-z0-9_-]{43})$" {
            alias $BASE/current/subscriptions/\$subscription_token.yaml;
            limit_except GET { deny all; }
        }
        location ~ "^/v/(?<v2rayn_token>[A-Za-z0-9_-]{43})$" {
            default_type text/plain;
            alias $BASE/current/subscriptions_v2rayn/\$v2rayn_token.txt;
            limit_except GET { deny all; }
        }
        location ~ "^/r/(?<shadowrocket_token>[A-Za-z0-9_-]{43})$" {
            default_type text/plain;
            alias $BASE/current/subscriptions_shadowrocket/\$shadowrocket_token.txt;
            limit_except GET { deny all; }
        }
        location / { return 404; }
    }
}
EOF
    python3 - "$directory/metadata.json" "$domain" "$port" <<'PY'
import json, sys
with open(sys.argv[1], 'w', encoding='utf-8') as stream:
    json.dump({'domain': sys.argv[2], 'port': int(sys.argv[3])}, stream)
    stream.write('\n')
PY
    chown root:"$SUB_ACCOUNT" "$directory" "$directory/nginx.conf" "$directory/server.crt" "$directory/server.key" "$directory/metadata.json"
    chmod 0750 "$directory"
    chmod 0640 "$directory/nginx.conf" "$directory/server.crt" "$directory/server.key" "$directory/metadata.json"
}

subscription_write_unit() {
    local nginx=$1 log_option=${2:-} temporary
    [[ -z "$log_option" || "$log_option" == '-e stderr' ]] || die 'Nginx 日志选项无效。'
    subscription_guard_unit
    [[ "$nginx" =~ ^/[A-Za-z0-9/._-]+$ ]] || die 'nginx 程序路径不符合要求。'
    root_readonly "$nginx"
    temporary=$(mktemp /etc/systemd/system/.jackie-anytls-sub-XXXXXXXX)
    cat >"$temporary" <<EOF
# Managed by $SUB_MARK
[Unit]
Description=AnyHarbor group subscriptions (isolated nginx)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$SUB_ACCOUNT
Group=$SUB_ACCOUNT
RuntimeDirectory=jackie-anytls-sub
RuntimeDirectoryMode=0700
ExecStartPre=$nginx $log_option -t -q -p $SUB_BASE/ -c $SUB_BASE/current/nginx.conf
ExecStart=$nginx $log_option -p $SUB_BASE/ -c $SUB_BASE/current/nginx.conf
KillSignal=SIGQUIT
TimeoutStopSec=10
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$temporary"
    mv -Tf -- "$temporary" "$SUB_UNIT"
    systemctl daemon-reload
}

subscription_healthy() {
    local directory=$1 domain port attempt code='' curl_status='' active=no
    domain=$(subscription_metadata "$directory" domain)
    port=$(subscription_metadata "$directory" port)
    for ((attempt=0; attempt<5; attempt++)); do
        if systemctl is-active --quiet "$SUB_SERVICE"; then
            active=yes
            curl_status=0
            code=$(curl -q --silent --show-error --output /dev/null --write-out '%{http_code}' \
                --noproxy '*' --connect-timeout 2 --max-time 4 --proto '=https' \
                --resolve "$domain:$port:127.0.0.1" "https://$domain:$port/" \
                2>"$directory/health-check.log") || curl_status=$?
            if [[ "$curl_status" == 0 && "$code" == 404 ]]; then
                rm -f -- "$directory/health-check.log"
                return 0
            fi
        else
            active=no
        fi
        sleep 1
    done
    printf '订阅本机检查失败：service-active=%s，上次 curl-exit=%s，HTTP=%s（预期 404）。\n' \
        "$active" "${curl_status:-未执行}" "${code:-无}" >&2
    # The probe requests only /, never a credential-bearing subscription URL.
    if [[ -s "$directory/health-check.log" ]]; then sed -n '1,8p' "$directory/health-check.log" >&2; fi
    return 1
}

subscription_restore_previous() {
    local previous=$1 was_active=$2 unit_backup=$3 was_enabled=$4 failed=0
    systemctl stop "$SUB_SERVICE" || failed=1
    if [[ -n "$previous" ]]; then atomic_link "$previous" "$SUB_BASE/current"; else rm -f -- "$SUB_BASE/current" || failed=1; fi
    if [[ -n "$unit_backup" ]]; then
        install -m 0644 -- "$unit_backup" "$SUB_UNIT" || failed=1
    else
        systemctl disable "$SUB_SERVICE" || failed=1
        rm -f -- "$SUB_UNIT" || failed=1
    fi
    systemctl daemon-reload || failed=1
    if [[ -n "$unit_backup" ]]; then
        if [[ "$was_enabled" == yes ]]; then systemctl enable "$SUB_SERVICE" || failed=1
        else systemctl disable "$SUB_SERVICE" || failed=1; fi
        if [[ "$was_active" == yes && -n "$previous" ]]; then
            if ! systemctl restart "$SUB_SERVICE" || ! subscription_healthy "$previous"; then failed=1; fi
        fi
    fi
    ((failed == 0))
}

subscription_default_settings() {
    local generation configuration='' domain certificate key port=9443 enabled
    generation=$(current)
    enabled=$(py get "$generation/state.json" subscription_enabled)
    subscription_guard_unit
    if [[ -e "$SUB_BASE/current" || -L "$SUB_BASE/current" ]]; then
        configuration=$(subscription_current_config)
        domain=$(subscription_metadata "$configuration" domain)
        port=$(subscription_metadata "$configuration" port)
        if [[ "$enabled" == 1 ]]; then
            [[ "$domain" == "$(py get "$generation/state.json" subscription_domain)" && "$port" == "$(py get "$generation/state.json" subscription_port)" ]] || die '订阅状态与已保存的 HTTPS 配置不一致，请先检查，或使用订阅菜单 8 手动配置。'
        fi
        certificate="$configuration/server.crt"
        key="$configuration/server.key"
    else
        [[ "$enabled" != 1 ]] || die '已启用的订阅缺少 HTTPS 配置，不能自动替换；请使用订阅菜单 8 手动配置。'
        domain=$(py get "$generation/state.json" sni)
        certificate="$generation/server.crt"
        key="$generation/server.key"
    fi
    [[ -n "$domain" && ! "$domain" =~ ^[0-9.]+$ && "$domain" != *:* ]] || die '当前配置没有可复用的 HTTPS 域名。请使用订阅菜单 8，或 any subscription enable 域名 完整证书链 私钥 端口，提供受信任 CA 证书。'
    [[ -f "$certificate" && -r "$certificate" && -f "$key" && -r "$key" ]] || die '可复用的证书或私钥缺失；请使用订阅菜单 8 手动导入。'
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || die '缺少系统 CA，请安装 ca-certificates。'
    if ! openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted "$certificate" \
        -purpose sslserver -verify_hostname "$domain" "$certificate" >/dev/null 2>&1; then
        die '现有证书不能用于受信任的 HTTPS 订阅（可能自签、过期或域名不匹配）。请使用订阅菜单 8，或 any subscription enable 域名 完整证书链 私钥 端口，重新导入有效证书；不会跳过证书验证。'
    fi
    printf '%s\n' "$domain" "$certificate" "$key" "$port"
}

subscription_manual_enable() {
    local domain certificate key port default_port=9443 configuration
    if [[ -L "$SUB_BASE/current" ]]; then
        configuration=$(subscription_current_config)
        default_port=$(subscription_metadata "$configuration" port)
    fi
    say '手动配置：可指定其他订阅域名，或重新导入续期后的完整证书链和私钥。'
    read -r -p '订阅域名（须已指向本机）：' domain || die '输入结束，未更改订阅。'
    read -r -p '完整证书链 PEM 绝对路径：' certificate || die '输入结束，未更改订阅。'
    read -r -p '私钥 PEM 绝对路径：' key || die '输入结束，未更改订阅。'
    say '更改订阅端口会改变订阅链接；请放行新端口并重新分发链接。'
    read -r -p "HTTPS 订阅端口 [$default_port]：" port || die '输入结束，未更改订阅。'
    [[ -n "$domain" && -n "$certificate" && -n "$key" ]] || die '域名、证书和私钥路径不能为空；未更改订阅。'
    subscription_enable "$domain" "$certificate" "$key" "${port:-$default_port}"
}

subscription_enable() {
    local domain=${1:-} certificate=${2:-} key=${3:-} port=${4:-9443}
    local nginx directory previous='' old_generation new_generation unit_backup='' was_active=no was_enabled=no old_port='' validated lua_path defaults answer
    local -a nginx_options=() settings=()
    (($# <= 4)) || die '用法：subscription enable [域名 完整证书链 私钥 [端口]]'
    if (($# == 0)); then
        defaults=$(subscription_default_settings)
        mapfile -t settings <<<"$defaults"
        domain=${settings[0]} certificate=${settings[1]} key=${settings[2]} port=${settings[3]}
        say "复用订阅域名：$domain"
        say "复用已导入的证书：$certificate"
        say '更换域名或导入续期证书，请使用订阅菜单 8，或 any subscription enable 域名 完整证书链 私钥 端口。'
        say '更改订阅端口会改变订阅链接；请放行新端口并重新分发链接。'
        read -r -p "HTTPS 订阅端口 [$port]：" answer || die '输入结束，未更改订阅。'
        port=${answer:-$port}
    else
        [[ -n "$domain" ]] || read -r -p '订阅域名（须已指向本机）：' domain
        [[ -n "$certificate" ]] || read -r -p '完整证书链 PEM 绝对路径：' certificate
        [[ -n "$key" ]] || read -r -p '私钥 PEM 绝对路径：' key
    fi
    validated=$(py validate "$domain" "$port")
    domain=$(sed -n '1p' <<<"$validated")
    port=$(sed -n '2p' <<<"$validated")
    [[ ! "$domain" =~ ^[0-9.]+$ ]] || die 'HTTPS 订阅请使用有受信任证书的域名。'
    [[ "$certificate" == /* && "$key" == /* && -f "$certificate" && -f "$key" ]] || die '证书/私钥必须是已存在文件的绝对路径。'
    nginx=$(command -v nginx) || die '未安装 nginx。请先安装发行版 nginx（例如 apt-get install nginx-light），再执行此命令。本工具不会自动安装或修改系统 nginx。'
    command -v runuser >/dev/null || die '缺少 runuser，请安装 util-linux。'
    nginx=$(readlink -f -- "$nginx")
    root_readonly "$nginx"
    subscription_guard_unit
    old_generation=$(current)
    if [[ -L "$SUB_BASE/current" ]]; then
        previous=$(subscription_current_config)
        old_port=$(subscription_metadata "$previous" port)
        if systemctl is-active --quiet "$SUB_SERVICE"; then was_active=yes; fi
        if systemctl is-enabled --quiet "$SUB_SERVICE"; then was_enabled=yes; fi
    fi
    if [[ "$was_active" != yes || "$old_port" != "$port" ]]; then free_port "$port"; fi
    subscription_initialize
    if runuser -u "$SUB_ACCOUNT" -- "$nginx" -h 2>&1 | grep -Eq -- '^[[:space:]]+-e[[:space:]]+file'; then nginx_options=(-e stderr); fi
    directory=$(mktemp -d "$SUB_BASE/releases/sub-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
    cp -L -- "$certificate" "$directory/server.crt"
    cp -L -- "$key" "$directory/server.key"
    subscription_validate_certificate "$directory" "$domain"
    chown root:"$SUB_ACCOUNT" "$directory"
    chmod 0750 "$directory"
    install -d -o "$SUB_ACCOUNT" -g "$SUB_ACCOUNT" -m 0700 /run/jackie-anytls-sub
    lua_path=$(subscription_nginx_lua_path "$directory" "$nginx" "${nginx_options[@]}")
    if [[ -n "$lua_path" ]]; then say "订阅 Nginx Lua 库：$lua_path"; fi
    subscription_write_config "$directory" "$domain" "$port" "$lua_path"
    clone_current
    new_generation=$WORK
    py edit "$WORK/state.json" subscription "$domain" "$port"
    finalize_generation
    # A v1.0 generation has no subscription exports; only its replacement does.
    if [[ -d "$old_generation/subscriptions" ]]; then subscription_publish_permissions "$old_generation"; fi
    if [[ -f "$SUB_UNIT" ]]; then
        unit_backup="$directory/previous-unit.backup"
        cp -- "$SUB_UNIT" "$unit_backup"
    fi
    # Test the candidate configuration before touching the running subscription.
    if ! runuser -u "$SUB_ACCOUNT" -- "$nginx" "${nginx_options[@]}" -t -q -p "$SUB_BASE/" -c "$directory/nginx.conf"; then die '订阅 nginx 配置检查失败，运行中的服务未改变。'; fi
    subscription_write_unit "$nginx" "${nginx_options[*]}"
    atomic_link "$directory" "$SUB_BASE/current"
    if ! systemctl restart "$SUB_SERVICE" || ! subscription_healthy "$directory"; then
        printf '启动日志命令：journalctl -u %s -n 60 --no-pager\n' "$SUB_SERVICE" >&2
        subscription_restore_previous "$previous" "$was_active" "$unit_backup" "$was_enabled" || die '新订阅失败，且旧订阅服务恢复检查失败，请保留配置并检查日志。'
        die '新订阅服务未通过本机 HTTPS 检查，原配置已恢复。'
    fi
    if ! (activate "$new_generation"); then
        subscription_restore_previous "$previous" "$was_active" "$unit_backup" "$was_enabled" || die '代理更新失败，且旧订阅服务恢复检查失败。'
        die '代理配置未激活，订阅服务已恢复原设置。'
    fi
    if ! systemctl enable "$SUB_SERVICE"; then
        say '订阅正在运行，但开机启动设置失败；请检查 systemctl enable jackie-anytls-sub.service。'
        return 1
    fi
    say "HTTPS 订阅已启用，TCP 端口：$port。本机证书验证通过；公网连通性和 DNS 仍须从客户端验证。"
    say '证书是复制导入的；原证书续期后，请使用订阅菜单 8，或带域名、证书、私钥和端口执行 subscription enable 重新导入。保持域名和端口时，订阅链接不变。'
    say '以下按分组显示所有订阅格式；只复制所属组对应客户端的完整 HTTPS 链接。'
    subscription_links all
}

subscription_refresh() {
    local generation configuration domain port
    generation=$(current)
    [[ $(py get "$generation/state.json" subscription_enabled) == 1 ]] || die '尚未开启在线订阅；请先执行 subscription enable。refresh 不会自动开启已关闭的订阅。'
    subscription_guard_unit
    configuration=$(subscription_current_config)
    domain=$(subscription_metadata "$configuration" domain)
    port=$(subscription_metadata "$configuration" port)
    [[ "$domain" == "$(py get "$generation/state.json" subscription_domain)" && "$port" == "$(py get "$generation/state.json" subscription_port)" ]] || die '订阅状态与已保存的 HTTPS 配置不一致，请人工检查后使用 subscription enable。'
    # Reuse validated local certificate copies and the existing transaction.
    # This refreshes routes; it does not fetch renewed certificates from BT/ACME.
    subscription_enable "$domain" "$configuration/server.crt" "$configuration/server.key" "$port"
}

subscription_links() {
    local format=${1:-all} identifier=${2:-} generation configuration
    (($# <= 2)) || die '用法：subscription links [all|clash|v2rayn|shadowrocket] [组ID]'
    [[ "$format" == all || "$format" == clash || "$format" == v2rayn || "$format" == shadowrocket ]] || die '订阅格式必须是 all、clash、v2rayn 或 shadowrocket。'
    generation=$(current)
    [[ $(py get "$generation/state.json" subscription_enabled) == 1 ]] || die '尚未开启在线订阅，请先使用 subscription enable，或导出本地配置。'
    if [[ "$format" == all || "$format" == v2rayn ]]; then
        configuration=$(subscription_current_config)
        grep -Fqx '# Subscription formats: clash,v2rayn' "$configuration/nginx.conf" || die '订阅服务尚未支持 v2rayN 路由；请先运行 any subscription refresh。'
        [[ -d "$generation/subscriptions_v2rayn" && ! -L "$generation/subscriptions_v2rayn" ]] || die '当前版本没有 v2rayN 导出；请先用新版运行 upgrade-manager，再运行 subscription refresh。'
        root_readonly "$generation/subscriptions_v2rayn"
    fi
    # Pin-mode requests are rejected or explained by the state helper. Only
    # advertise /r when a PKI generation and the installed route both exist.
    if [[ "$format" == all || "$format" == shadowrocket ]] && [[ $(py get "$generation/state.json" tls_verify) == pki ]]; then
        configuration=$(subscription_current_config)
        grep -Fqx '# Subscription format: shadowrocket' "$configuration/nginx.conf" || die '订阅服务尚未支持 Shadowrocket 路由；请先运行 any subscription refresh。'
        [[ -d "$generation/subscriptions_shadowrocket" && ! -L "$generation/subscriptions_shadowrocket" ]] || die '当前配置没有 Shadowrocket 订阅导出；请先运行 any subscription refresh。'
        root_readonly "$generation/subscriptions_shadowrocket"
    fi
    if [[ "$format" == all ]]; then py links-all "$generation/state.json" "$identifier"
    else py links "$generation/state.json" "$format" "$identifier"; fi
}

subscription_check() {
    local generation
    (($# <= 1)) || die '用法：subscription check [组ID]'
    generation=$(current)
    [[ $(py get "$generation/state.json" subscription_enabled) == 1 ]] || die '尚未开启在线订阅，请先使用 subscription enable。'
    subscription_guard_unit
    subscription_current_config >/dev/null
    if [[ -n "${1:-}" ]]; then py check-subscriptions "$generation" "$1"
    else py check-subscriptions "$generation"; fi
}

subscription_off() {
    local new_generation was_active=no was_enabled=no
    current >/dev/null
    if [[ -e "$SUB_BASE" ]]; then subscription_owned; subscription_guard_unit; fi
    if [[ -f "$SUB_UNIT" ]]; then
        if systemctl is-active --quiet "$SUB_SERVICE"; then was_active=yes; fi
        if systemctl is-enabled --quiet "$SUB_SERVICE"; then was_enabled=yes; fi
    fi
    clone_current
    new_generation=$WORK
    py edit "$WORK/state.json" subscription-off
    finalize_generation
    if [[ -f "$SUB_UNIT" ]]; then
        if ! systemctl disable --now "$SUB_SERVICE"; then die '订阅服务未能停用，未改动代理配置。'; fi
    fi
    if ! (activate "$new_generation"); then
        if [[ -f "$SUB_UNIT" && -L "$SUB_BASE/current" ]]; then
            if [[ "$was_enabled" == yes ]]; then systemctl enable "$SUB_SERVICE" || true; fi
            if [[ "$was_active" == yes ]]; then systemctl restart "$SUB_SERVICE" || true; fi
        fi
        die '代理配置更新失败，保留原订阅设置。'
    fi
    say '在线订阅已关闭。代理账号仍有效；撤销访问请使用 group disable 或 group rotate。'
}

subscription_status() {
    local generation configuration
    generation=$(current)
    if [[ $(py get "$generation/state.json" subscription_enabled) != 1 ]]; then
        if [[ -d "$SUB_BASE" && -L "$SUB_BASE/current" ]]; then
            say '在线订阅已关闭；证书和配置仍保留。使用 subscription enable 可重新开启。'
        else
            say '尚未启用在线订阅；未完成的准备文件（如有）可在下次 enable 时复用。'
        fi
        return
    fi
    if [[ ! -d "$SUB_BASE" ]]; then say '尚未配置在线订阅。'; return; fi
    subscription_guard_unit
    configuration=$(subscription_current_config)
    systemctl --no-pager --lines=0 status "$SUB_SERVICE" || true
    say "订阅域名：$(subscription_metadata "$configuration" domain)，TCP 端口：$(subscription_metadata "$configuration" port)"
    openssl x509 -in "$configuration/server.crt" -noout -dates
    if grep -Fqx '# Subscription formats: clash,v2rayn' "$configuration/nginx.conf"; then
        say '已配置 Clash 与 v2rayN 订阅格式。'
    else
        say '当前仅配置 Clash 订阅；运行 subscription refresh 可添加 v2rayN 路由。'
    fi
    if [[ $(py get "$generation/state.json" tls_verify) == pki ]]; then
        if grep -Fqx '# Subscription format: shadowrocket' "$configuration/nginx.conf" && [[ -d "$generation/subscriptions_shadowrocket" ]]; then
            say '已配置 Shadowrocket 订阅格式。'
        else say 'Shadowrocket 订阅尚未就绪；运行 any subscription refresh 可更新发布格式。'; fi
    else
        say '当前固定指纹模式不提供 Shadowrocket 格式；需要受信任 CA 证书。'
    fi
    if subscription_healthy "$configuration"; then say '本机 HTTPS 检查通过。'; else say '订阅服务未通过本机 HTTPS 检查。'; fi
}

subscription_stop_if_owned() {
    [[ -e "$SUB_BASE" || -e "$SUB_UNIT" || -L "$SUB_UNIT" ]] || return 0
    subscription_guard_unit
    # An interrupted first preparation may leave data but has not created a
    # service. It must not prevent uninstalling the independent proxy service.
    [[ -f "$SUB_UNIT" ]] || return 0
    subscription_owned
    systemctl disable --now "$SUB_SERVICE"
}

subscription_restore_if_configured() {
    local generation configuration
    generation=$(current)
    if ! python3 - "$generation/state.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as stream:
    sys.exit(0 if json.load(stream).get('subscription') else 1)
PY
    then return 0; fi
    configuration=$(subscription_current_config)
    subscription_guard_unit
    [[ -f "$SUB_UNIT" ]] || die '订阅配置存在但专用服务文件缺失，请重新执行 subscription enable。'
    subscription_publish_permissions "$generation"
    systemctl enable "$SUB_SERVICE"
    systemctl restart "$SUB_SERVICE"
    subscription_healthy "$configuration" || die '订阅服务恢复后未通过本机 HTTPS 检查。'
}

subscription_stop_for_uninstall() { subscription_stop_if_owned; }

subscription_command() {
    local action=${1:-menu} choice menu_generation identifier
    shift || true
    if [[ "$action" == menu ]]; then
        menu_generation=$(current)
        ui_heading '在线订阅' page
        ui_note '模式    HTTPS，每个分组独立链接'
        if [[ $(py get "$menu_generation/state.json" subscription_enabled) == 1 ]]; then
            if systemctl is-active --quiet "$SUB_SERVICE"; then
                ui_note '状态    已开启，订阅服务运行中'
            else
                ui_note '状态    已配置，订阅服务未运行'
            fi
            ui_note "域名    $(py get "$menu_generation/state.json" subscription_domain)"
            ui_note "端口    $(py get "$menu_generation/state.json" subscription_port)"
        else
            ui_note '状态    未开启，本地配置仍可导入'
            ui_note '启用需要域名及受信任的 HTTPS 证书'
        fi
        ui_section '订阅配置'
        ui_item 1 '启用 / 调整订阅端口（复用域名证书）'
        ui_item 2 '查看服务状态与证书'
        ui_item 6 '刷新订阅发布格式'
        ui_item 7 '检查各格式订阅实际内容'
        ui_item 8 '手动配置域名 / 导入续期证书'
        ui_section '链接分发'
        ui_item 3 '按组查看全部格式的订阅链接'
        ui_item 5 '导出 v2rayN 订阅链接'
        ui_item 9 '导出 Shadowrocket 订阅链接（可信证书）'
        ui_note '选择后显示访问链接，只发给对应分组'
        ui_section '停用与返回'
        ui_item 4 '关闭在线订阅（代理账号仍有效）'
        ui_item 0 '返回主菜单'
        read -r -p $'\n请输入选项编号：' choice
        case "$choice" in
            1) action=enable;; 2) action=status;;
            3) menu_select_group identifier yes; action=links; set -- all "$identifier";;
            4) action=off;;
            5) menu_select_group identifier yes; action=links; set -- v2rayn "$identifier";;
            6) action=refresh;;
            7) menu_select_group identifier; action=check; set -- "$identifier";;
            8) action=manual;;
            9) menu_select_group identifier yes; action=links; set -- shadowrocket "$identifier";;
            0) return;; *) die '无效选择。';;
        esac
    fi
    case "$action" in
        enable) subscription_enable "$@";;
        manual) subscription_manual_enable;;
        refresh) subscription_refresh;;
        off|disable) subscription_off;;
        status) subscription_status;;
        links) subscription_links "$@";;
        check) subscription_check "$@";;
        *) die '用法：subscription enable [域名 完整证书链 私钥 [端口9443]] | manual | refresh | status | check [组ID] | links [all|clash|v2rayn|shadowrocket] [组ID] | off';;
    esac
}
