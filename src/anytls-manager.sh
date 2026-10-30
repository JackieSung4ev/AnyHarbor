#!/usr/bin/env bash
# Original maintenance wrapper. Downloads only official SagerNet release binaries.
# Sources and verification limits are documented in README.txt.
set -Eeuo pipefail
umask 077
export LC_ALL=C
readonly BASE=/opt/jackie-anytls SERVICE=jackie-anytls.service ACCOUNT=jackie-anytls
readonly UNIT=/etc/systemd/system/jackie-anytls.service MANAGER=/usr/local/sbin/jackie-anytls
readonly APP_NAME=AnyHarbor
# Used by the sourced anytls-runtime.sh module.
# shellcheck disable=SC2034
readonly SHORT_MANAGER=/usr/local/sbin/any
readonly OWNER_MARK=jackie-anytls-manager-v1 DEFAULT_VERSION=1.14.4
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
WORK=''
readonly MANAGER_VERSION=1.7.4
say() { printf '%s\n' "$*"; }
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
ui_color() {
    [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR+x} ]]
}
ui_heading() {
    # "page" redraws this menu; omit it mid-flow so previous steps remain visible.
    local width=72
    if [[ ${2:-} == page && -t 1 && ${TERM:-dumb} != dumb ]]; then
        printf '\033[H\033[2J'
    fi
    if ui_color; then
        [[ ${COLUMNS:-} =~ ^[0-9]+$ ]] && width=$COLUMNS
        (( width < 40 )) && width=40
        (( width > 72 )) && width=72
        printf '\n\033[1;37;44m%-*s\033[0m\n\n' "$width" "  $1"
    else
        printf '\n== %s ==\n\n' "$1"
    fi
}
ui_section() {
    if ui_color; then
        printf '\n\033[1;33m  %s\033[0m\n' "$1"
    else
        printf '\n  %s\n' "$1"
    fi
}
ui_item() {
    if ui_color; then
        printf '  \033[1;32m%2s)\033[0m  %s\n' "$1" "$2"
    else
        printf '  %2s)  %s\n' "$1" "$2"
    fi
}
ui_note() {
    if ui_color; then
        printf '  \033[36m· %s\033[0m\n' "$1"
    else
        printf '  · %s\n' "$1"
    fi
}
ui_warn() {
    if ui_color; then
        printf '  \033[1;31m· %s\033[0m\n' "$1"
    else
        printf '  · %s\n' "$1"
    fi
}
ui_prompt() {
    local target=$1 text=$2 answer
    if [[ -t 2 && ${TERM:-dumb} != dumb && -z ${NO_COLOR+x} ]]; then
        printf '\n\033[1;36m%s\033[0m ' "$text" >&2
    else
        printf '\n%s ' "$text" >&2
    fi
    IFS= read -r answer || return 1
    printf -v "$target" '%s' "$answer"
}
cleanup() {
    if [[ -n "$WORK" && "$WORK" == "$BASE/releases/"* && -d "$WORK" && ! -L "$WORK" ]]; then
        rm -f -- "$WORK/archive.tar.gz" "$WORK/release.json" "$WORK/tls-check.txt"
    fi
}
trap cleanup EXIT
trap 'printf "操作停止（第 %s 行）。请保留上方错误；脚本不会关闭防火墙。\n" "$LINENO" >&2' ERR

# Helpers are installed together; never download or execute a remote script.
HELPER_DIR=$(dirname -- "$SELF")
if [[ "$SELF" == "$MANAGER" ]]; then HELPER_DIR="$BASE/lib"; fi
py() { python3 "$HELPER_DIR/anytls-state.py" "$@"; }


root_and_tools() {
    [[ "$EUID" -eq 0 ]] || die '请使用 root 运行：sudo bash anytls-manager.sh'
    [[ $(uname -s) == Linux ]] || die '本工具用于 Linux + systemd，不在 Windows 本机安装。'
    local missing=() item
    for item in python3 curl openssl sha256sum flock ss systemctl timeout install stat readlink getent useradd; do
        command -v "$item" >/dev/null || missing+=("$item")
    done
    if ((${#missing[@]})); then
        say "缺少命令：${missing[*]}"
        die '请先安装依赖，例如 apt-get install -y curl ca-certificates openssl python3 iproute2 util-linux；脚本不会自动刷新或修改 APT 源。'
    fi
    [[ -d /run/systemd/system ]] || die '未检测到运行中的 systemd。不要直接在普通 Docker 容器里安装服务。'
    root_readonly "$HELPER_DIR/anytls-state.py"
    root_readonly "$HELPER_DIR/anytls-subscription.sh"
    root_readonly "$HELPER_DIR/anytls-runtime.sh"
    root_readonly "$HELPER_DIR/anytls-update.py"
}
root_readonly() {
    local path=$1
    [[ -e "$path" && ! -L "$path" && $(stat -c %u "$path") == 0 ]] || die "路径不属于 root 或是链接：$path"
    (( (8#$(stat -c %a "$path") & 0022) == 0 )) || die "路径可被非 root 修改：$path"
}
guard_generation() {
    local d=$1 item
    [[ $(dirname -- "$d") == "$BASE/releases" && -d "$d" ]] || die '版本目录不在预期位置。'
    root_readonly "$d"
    for item in sing-box config.json state.json server.crt server.key; do
        [[ -f "$d/$item" ]] || die "缺少版本文件：$item"
        root_readonly "$d/$item"
    done
}
owned_base() {
    [[ -d "$BASE" && ! -L "$BASE" && -f "$BASE/.owner" && ! -L "$BASE/.owner" ]] || die '未找到本工具管理的安装。'
    [[ $(cat "$BASE/.owner") == "$OWNER_MARK" && $(stat -c %u "$BASE") == 0 ]] || die '安装目录的归属标记不符合要求。'
    (( (8#$(stat -c %a "$BASE") & 0022) == 0 )) || die '安装目录可被非 root 修改，停止操作。'
    [[ -d "$BASE/releases" && ! -L "$BASE/releases" ]] || die '版本目录不符合要求。'
    root_readonly "$BASE/releases"; root_readonly "$BASE/.owner"
}
lock_base() {
    if [[ -e "$BASE/.lock" || -L "$BASE/.lock" ]]; then
        [[ -f "$BASE/.lock" ]] || die '维护锁不是常规文件。'
        root_readonly "$BASE/.lock"
    fi
    if [[ ${GZ_ANYTLS_INHERIT_LOCK:-} == 1 ]]; then
        [[ -f "$BASE/.lock" && -e /proc/$$/fd/9 ]] || die '继承的维护锁缺失。'
        [[ $(stat -Lc '%d:%i' /proc/$$/fd/9) == "$(stat -c '%d:%i' "$BASE/.lock")" ]] || die '继承的维护锁不属于当前安装。'
        flock -n 9 || die '无法取得继承的维护锁。'
        unset GZ_ANYTLS_INHERIT_LOCK
    else
        exec 9>"$BASE/.lock"
        flock -n 9 || die '已有维护操作正在运行，请稍后重试。'
    fi
}
current() {
    owned_base
    [[ -L "$BASE/current" ]] || die '尚未完成安装；请重新运行 install。'
    local d; d=$(readlink -f -- "$BASE/current")
    [[ "$d" == "$BASE/releases/"* && -d "$d" && -f "$d/state.json" ]] || die '当前版本指针异常。'
    guard_generation "$d"
    printf '%s\n' "$d"
}
free_port() {
    local output; output=$(ss -H -ltn "( sport = :$1 )") || die '无法检查端口占用。'
    [[ -z "$output" ]] || die "TCP $1 已被占用，请选择其他端口；不会停止占用它的服务。"
}
new_generation() {
    WORK=$(mktemp -d "$BASE/releases/release-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX")
}
clone_current() {
    local old; old=$(current); new_generation
    cp -- "$old/state.json" "$old/server.crt" "$old/server.key" "$WORK/"
    ln -- "$old/sing-box" "$WORK/sing-box"
}
fetch_core() {
    local wanted=${1#v} arch url metadata digest version actual
    case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die '目前只支持 Linux amd64/arm64。';; esac
    [[ "$wanted" == latest || "$wanted" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die '版本必须是稳定版编号，例如 1.14.4，或 latest。'
    if [[ "$wanted" == latest ]]; then url=https://api.github.com/repos/SagerNet/sing-box/releases/latest
    else url="https://api.github.com/repos/SagerNet/sing-box/releases/tags/v$wanted"; fi
    say '正在读取 sing-box 官方发布信息……'
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 90 --retry 2 "$url" -o "$WORK/release.json"
    metadata=$(py release "$WORK/release.json" "$wanted" "$arch")
    version=$(sed -n '1p' <<<"$metadata"); url=$(sed -n '2p' <<<"$metadata"); digest=$(sed -n '3p' <<<"$metadata")
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die '官方发布未提供有效 SHA256，停止下载。'
    say "下载官方 sing-box $version ($arch)，完成后校验 SHA256……"
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 600 --retry 2 "$url" -o "$WORK/archive.tar.gz"
    actual=$(sha256sum "$WORK/archive.tar.gz"); actual=${actual%% *}
    [[ "$actual" == "$digest" ]] || die '下载文件的 SHA256 不匹配，未执行或替换核心。'
    rm -f -- "$WORK/sing-box"
    py extract "$WORK/archive.tar.gz" "$WORK/sing-box" "$version" "$arch"
    chmod 0755 "$WORK/sing-box"
    "$WORK/sing-box" version
    py edit "$WORK/state.json" version "$version" "$digest"
    rm -f -- "$WORK/archive.tar.gz" "$WORK/release.json"
}
finalize_generation() {
    py render "$WORK"
    chown root:"$ACCOUNT" "$WORK" "$WORK/config.json" "$WORK/server.crt" "$WORK/server.key"
    chmod 0750 "$WORK"
    chmod 0640 "$WORK/config.json" "$WORK/server.crt" "$WORK/server.key"
    chmod 0600 "$WORK/state.json"
    local f
    for f in "$WORK/mihomo-node.yaml" "$WORK/mihomo-profile.yaml"; do
        [[ ! -f "$f" ]] || chmod 0600 "$f"
    done
    subscription_publish_permissions "$WORK"
    guard_generation "$WORK"
    "$WORK/sing-box" check -c "$WORK/config.json"
}
atomic_link() {
    local target=$1 link=$2 temp="$BASE/.link-$$-$RANDOM"
    ln -s -- "$target" "$temp" || die "无法创建版本切换链接：$link"
    mv -Tf -- "$temp" "$link" || die "无法切换版本链接：$link"
}
tls_probe() {
    local d=$1 p identity verify
    local ca_args=()
    p=$(py get "$d/state.json" port); identity=$(py get "$d/state.json" sni)
    if [[ "$identity" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then verify=-verify_ip; else verify=-verify_hostname; fi
    if [[ $(py get "$d/state.json" tls_verify) == pki ]]; then
        ca_args=(-CAfile /etc/ssl/certs/ca-certificates.crt)
    else
        ca_args=(-partial_chain -CAfile "$d/server.crt")
    fi
    timeout 4 openssl s_client -connect "127.0.0.1:$p" -servername "$identity" -alpn h2 \
        -verify_return_error "${ca_args[@]}" "$verify" "$identity" \
        </dev/null >"$d/tls-check.txt" 2>&1 || return 1
    grep -q 'ALPN protocol: h2' "$d/tls-check.txt"
}
healthy() {
    local d=$1 attempt
    for ((attempt=0; attempt<5; attempt++)); do
        if systemctl is-active --quiet "$SERVICE" && tls_probe "$d"; then return 0; fi
        sleep 1
    done
    return 1
}
activate() {
    local next=$1 old='' older=''
    require_owned_unit
    guard_generation "$next"
    [[ ! -L "$BASE/current" ]] || old=$(current)
    [[ ! -L "$BASE/previous" ]] || older=$(readlink -f "$BASE/previous")
    # Save the known-good pointer before exposing a candidate to systemd.
    [[ -z "$old" ]] || atomic_link "$old" "$BASE/previous"
    atomic_link "$next" "$BASE/current"
    if ! systemctl restart "$SERVICE" || ! healthy "$next"; then
        say '新配置未通过服务/本机 TLS 检查，正在恢复之前的版本……'
        if [[ -n "$old" ]]; then
            atomic_link "$old" "$BASE/current"
            if ! systemctl restart "$SERVICE" || ! healthy "$old"; then
                die '已恢复旧指针，但旧服务仍未通过检查。请运行 logs，保留版本目录。'
            fi
            if [[ -n "$older" ]]; then atomic_link "$older" "$BASE/previous"; else rm -f -- "$BASE/previous"; fi
        else
            systemctl stop "$SERVICE" || true
            rm -f -- "$BASE/current"
        fi
        die '此次变更未生效。旧版本和配置已保留。'
    fi
    [[ -z "$old" || "$old" == "$next" ]] || atomic_link "$old" "$BASE/previous"
    say '服务已启动，本机 TLS 与证书检查通过。公网连通性需另行验证。'
}
require_owned_unit() {
    if [[ ! -f "$UNIT" || -L "$UNIT" ]] || ! grep -qx '# Managed by jackie-anytls-manager-v1' "$UNIT"; then die '服务文件不是本工具管理的，停止操作。'; fi
    root_readonly "$UNIT"
    check_unit_overrides
}
check_unit_overrides() {
    local dir name
    for dir in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        for name in "$SERVICE.d" jackie-.service.d; do
            [[ ! -e "$dir/$name" && ! -L "$dir/$name" ]] || die "发现额外的服务覆盖目录，请先人工检查：$dir/$name"
        done
    done
    for dir in /run/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [[ ! -e "$dir/$SERVICE" && ! -L "$dir/$SERVICE" ]] || die "发现其他位置的同名服务，拒绝接管：$dir/$SERVICE"
    done
}
write_unit() {
    check_unit_overrides
    if [[ -e "$UNIT" || -L "$UNIT" ]]; then
        if [[ -L "$UNIT" ]] || ! grep -qx '# Managed by jackie-anytls-manager-v1' "$UNIT"; then die '同名服务不是本工具管理的，拒绝覆盖。'; fi
        root_readonly "$UNIT"
    fi
    local temp_unit; temp_unit=$(mktemp /etc/systemd/system/.jackie-anytls-XXXXXXXX)
    cat >"$temp_unit" <<'UNIT'
# Managed by jackie-anytls-manager-v1
[Unit]
Description=AnyHarbor (official sing-box)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=jackie-anytls
Group=jackie-anytls
WorkingDirectory=/opt/jackie-anytls
ExecStart=/opt/jackie-anytls/current/sing-box run -c /opt/jackie-anytls/current/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
UNIT
    chmod 0644 "$temp_unit"
    mv -Tf -- "$temp_unit" "$UNIT"
    systemctl daemon-reload
}
install_read() {
    local target=$1 prompt=$2 fallback=${3:-} answer
    printf '%s' "$prompt" >&2
    if ! IFS= read -r answer; then
        printf '\n' >&2
        die '安装已取消：输入结束，尚未创建安装目录或账号。重新运行 install 可再次开始。'
    fi
    [[ -n "$answer" ]] || answer=$fallback
    printf -v "$target" '%s' "$answer"
}
install_server() {
    local address=${1:-} p=${2:-8443} prefix=GZ mode=2 cert='' key='' cert_default key_default
    (($# <= 2)) || die '用法：install 打开向导；install 地址 [端口] 使用兼容自签模式。'
    py apt-suite >/dev/null
    check_unit_overrides
    if [[ -L "$BASE/current" ]]; then die '已经安装。请使用菜单中的改端口、换密码或更新功能。'; fi
    ui_heading "$APP_NAME $MANAGER_VERSION · 首次安装" page
    ui_section '[1/4] 检查安装参数'
    if (($# == 0)); then
        ui_note '填写当前服务器的域名及证书路径；全部检查通过后才创建账号和安装服务。'
        ui_item 1 '域名 + 已有可信 SSL 证书（默认）'
        ui_item 2 '公网 IPv4 + 本机自签证书（测试模式）'
        while :; do
            install_read mode '安装模式 [1]：' 1
            [[ "$mode" == 1 || "$mode" == 2 ]] && break
            ui_note '请输入 1 或 2。'
        done
        if [[ "$mode" == 1 ]]; then
            while :; do
                install_read address '服务器域名（例如 proxy.example.com，不含 https://）：'
                if address=$(py validate-domain "$address"); then break; fi
                ui_note '域名无效，请重新输入；输入结束可取消安装。'
            done
            cert_default="/www/server/panel/vhost/cert/$address/fullchain.pem"
            key_default="/www/server/panel/vhost/cert/$address/privkey.pem"
            while :; do
                install_read cert "完整证书链绝对路径 [$cert_default]：" "$cert_default"
                install_read key "未加密私钥绝对路径 [$key_default]：" "$key_default"
                if [[ "$cert" != /* || "$key" != /* || ! -f "$cert" || ! -f "$key" || ! -r "$cert" || ! -r "$key" ]]; then
                    ui_note '证书和私钥必须是服务器上已存在、可读文件的绝对路径，请重新输入两项。'
                    continue
                fi
                if py check-cert "$cert" "$key" "$address" pki >/dev/null; then break; fi
                ui_note '证书检查未通过：请核对域名、有效期、完整链及私钥是否匹配，再重新输入两项。'
            done
            ui_note '可信证书检查通过。证书会复制到本工具的配置目录。'
        else
            ui_note '自签测试模式：客户端使用固定证书指纹；以后换证需要更新客户端配置。'
            while :; do
                install_read address '当前服务器公网 IPv4：'
                if address=$(py validate-ip "$address"); then break; fi
                ui_note '请输入有效 IPv4 地址。'
            done
        fi
        while :; do
            install_read p 'AnyTLS TCP 端口 [8443]：' 8443
            if py validate "$address" "$p" >/dev/null && (free_port "$p"); then break; fi
            ui_note '端口应为未占用的 1024..65535，请重新输入。'
        done
        while :; do
            install_read prefix '本机节点名称前缀 [GZ]：' GZ
            if prefix=$(py validate-prefix "$prefix"); then break; fi
            ui_note '前缀应为 1..32 个可打印字符，不能有首尾空格，请重新输入。'
        done
    else
        ui_note '兼容命令模式：使用自签证书和固定证书指纹；如需可信域名证书，请不带地址运行 install。'
        py validate "$address" "$p" >/dev/null
    fi
    free_port "$p"
    ui_note "连接地址：$address:$p"
    ui_note "节点前缀：$prefix；初始分组：10 个"
    ui_section '[2/4] 创建本机配置与分组'
    manager_short_command_guard
    if [[ ! -e "$BASE" && ! -L "$BASE" ]]; then
        getent passwd "$ACCOUNT" >/dev/null && die '同名系统用户已存在，拒绝接管。'
        [[ ! -e "$UNIT" && ! -L "$UNIT" && ! -e "$MANAGER" && ! -L "$MANAGER" ]] || die '同名服务或管理命令已存在，拒绝覆盖。'
        install -d -m 0750 "$BASE" "$BASE/releases"
        printf '%s\n' "$OWNER_MARK" >"$BASE/.owner"
        useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin "$ACCOUNT"
        touch "$BASE/.user-created"
    fi
    owned_base; lock_base
    if [[ ! -f "$BASE/.user-created" ]] || ! getent passwd "$ACCOUNT" >/dev/null; then die '服务用户状态不一致，请检查首次安装报错。'; fi
    chown root:"$ACCOUNT" "$BASE" "$BASE/releases"
    chmod 0750 "$BASE" "$BASE/releases"
    new_generation
    py init "$WORK/state.json" "$address" "$p"
    py edit "$WORK/state.json" prefix "$prefix"
    if [[ "$mode" == 1 ]]; then
        cp -L -- "$cert" "$WORK/server.crt"
        cp -L -- "$key" "$WORK/server.key"
        py edit "$WORK/state.json" import-cert "$address" pki
    else py certificate "$WORK"; fi
    ui_section '[3/4] 下载官方核心并验证配置'
    fetch_core "$DEFAULT_VERSION"
    finalize_generation
    ui_section '[4/4] 启动服务并检查本机 TLS'
    write_unit
    install_manager
    activate "$WORK"
    systemctl enable "$SERVICE"
    ui_heading '安装完成'
    ui_note '已设置开机启动。运行 any 打开维护菜单。'
    ui_note "公网检查：Test-NetConnection $address -Port $p"
    if [[ "$mode" == 1 ]]; then
        ui_note '已使用可信域名证书；原证书续期后，请运行 any import-cert 重新导入。'
    fi
    show_summary
}
ui_status_summary() {
    local d status color
    if [[ -L "$BASE/current" ]]; then
        d=$(current)
        if systemctl is-active --quiet "$SERVICE"; then
            status=运行中
            color='1;32'
        else
            status=未运行
            color='1;31'
        fi
        if ui_color; then
            printf '  \033[36m服务\033[0m    \033[%sm%s\033[0m\n' "$color" "$status"
            printf '  \033[36m地址\033[0m    %s:%s\n' "$(py get "$d/state.json" server)" "$(py get "$d/state.json" port)"
            printf '  \033[36m前缀\033[0m    %s\n' "$(py get "$d/state.json" node_prefix)"
            printf '  \033[36m分组\033[0m    %s/%s 启用\n' "$(py get "$d/state.json" active_group_count)" "$(py get "$d/state.json" group_count)"
            printf '  \033[36m版本\033[0m    %s\n' "$MANAGER_VERSION"
        else
            printf '  服务    %s\n' "$status"
            printf '  地址    %s:%s\n' "$(py get "$d/state.json" server)" "$(py get "$d/state.json" port)"
            printf '  前缀    %s\n' "$(py get "$d/state.json" node_prefix)"
            printf '  分组    %s/%s 启用\n' "$(py get "$d/state.json" active_group_count)" "$(py get "$d/state.json" group_count)"
            printf '  版本    %s\n' "$MANAGER_VERSION"
        fi
    elif [[ -e "$BASE" || -L "$BASE" ]]; then
        ui_note '状态：安装尚未完成；保留已有文件，修正报错后可重新运行 install。'
    else
        ui_note '状态：尚未安装；选择 9 打开安装向导。'
    fi
}
show_summary() {
    local d; d=$(current)
    ui_section '分组（不显示密码）'
    py list-ui "$d/state.json"
    ui_section '导入客户端'
    ui_note "各组完整配置：$BASE/current/profiles/<组ID>.yaml"
    ui_note "v2rayN 分享链接：$BASE/current/v2rayn/<组ID>.txt"
    if [[ $(py get "$d/state.json" tls_verify) == pki ]]; then
        if [[ -d "$d/shadowrocket" ]]; then ui_note "Shadowrocket 分享链接：$BASE/current/shadowrocket/<组ID>.txt"
        else ui_note '当前配置尚未生成 Shadowrocket 格式；请先运行 any upgrade-manager。'; fi
    else
        ui_note '当前使用固定证书指纹；Shadowrocket 格式仅在导入受信任 CA 证书后提供，不会跳过证书验证。'
    fi
    ui_note '运行 any export <组ID> 查看该组所有支持的格式；运行 any groups 打开分组管理。'
    ui_note '需要单独保存文件时，使用 export <组ID> clash、v2rayn 或 shadowrocket。'
    if [[ $(py get "$d/state.json" subscription_enabled) == 1 ]]; then
        ui_note '在线订阅已配置。运行 any sub <组ID> 查看该组所有格式的订阅链接。'
    else
        ui_note '尚未开启在线订阅；本地配置文件可直接导入。'
    fi
}
show_export() {
    (($# <= 2)) || die '用法：export [组ID] [all|clash|v2rayn|shadowrocket]'
    local d format=${2:-all} helper
    case "$format" in
        all) helper=export-all;; clash) helper='export';; v2rayn) helper=export-v2rayn;;
        shadowrocket) helper=export-shadowrocket;;
        *) die '导出格式必须是 all、clash、v2rayn 或 shadowrocket。';;
    esac
    d=$(current)
    if [[ -z ${1:-} && $(py get "$d/state.json" active_group_count) != 1 ]]; then
        show_summary >&2
        printf '%s\n' '请指定组ID，例如：any export athena' >&2
        return 1
    fi
    printf '%s\n' '以下内容包含该分组密码，仅向本组成员分发；组合输出请按格式分别复制。' >&2
    py "$helper" "$d/state.json" "$d" "${1:-}"
}
show_v2rayn_export() {
    (($# <= 1)) || die '用法：export-v2rayn [组ID]'
    show_export "${1:-}" v2rayn
}
show_clash_export() {
    (($# <= 1)) || die '用法：export-clash [组ID]'
    show_export "${1:-}" clash
}
show_shadowrocket_export() {
    (($# <= 1)) || die '用法：export-shadowrocket [组ID]'
    show_export "${1:-}" shadowrocket
}
group_command() {
    local action=${1:-list} id=${2:-} label=${3:-} d automatic=0 egress=direct
    d=$(current)
    if [[ "$action" == list ]]; then py list "$d/state.json"; return; fi
    case "$action" in
        add)
            if (($# == 1)); then automatic=1
            elif (($# != 3)) || [[ -z "$id" || -z "$label" ]]; then
                die '用法：any add，或 any group add [组ID 显示名称]'
            fi
            if [[ -t 0 ]]; then warp_select_egress egress; fi;;
        egress)
            if (($# != 3)) || [[ -z "$id" || ( "$label" != direct && "$label" != warp ) ]]; then
                die '用法：any group egress 组ID direct|warp'
            fi
            if [[ $(py group-egress "$d/state.json" "$id") == "$label" ]]; then
                say '该分组出口没有改变。'; return
            fi
            egress=$label;;
        rename)
            [[ -n "$id" ]] || read -r -p '组ID（小写字母/数字/连字符，例如 athena）：' id
            [[ -n "$label" ]] || read -r -p '组显示名称：' label;;
        rotate|disable|enable|remove)
            [[ -n "$id" ]] || read -r -p '组ID：' id;;
        *) die '分组命令：list/add/rename/rotate/disable/enable/remove/egress';;
    esac
    if [[ "$egress" == warp ]] ||
       { [[ "$action" == enable ]] && [[ $(py group-egress "$d/state.json" "$id") == warp ]]; }; then
        warp_require_ready
    fi
    clone_current
    if [[ "$action" == add ]]; then
        if ((automatic)); then id=$(py group "$WORK/state.json" add)
        else id=$(py group "$WORK/state.json" add "$id" "$label"); fi
        if [[ "$egress" == warp ]]; then py group "$WORK/state.json" egress "$id" warp; fi
    elif [[ "$action" == rename || "$action" == egress ]]; then py group "$WORK/state.json" "$action" "$id" "$label"
    else py group "$WORK/state.json" "$action" "$id"; fi
    finalize_generation; activate "$WORK"
    say '分组变更已生效。应用配置会短暂重启整个 AnyTLS 服务。'
    if [[ "$action" == rotate || "$action" == disable || "$action" == enable ]]; then
        say '该组旧代理密码和旧订阅令牌已作废；其余组凭据保持不变。'
    fi
    if [[ "$action" == egress ]]; then
        say "该组出口已设为 $egress；密码、订阅链接和入站端口不变。请刷新订阅以更新 UDP 提示。"
    fi
    show_summary
    if [[ "$action" == add ]]; then
        say "已新增分组，ID：$id；独立密码和订阅令牌已生成。"
        say "全部格式导出：any export $id"
        say "全部格式订阅：any sub $id（需已开启在线订阅）"
    fi
}
group_menu() {
    local choice identifier egress
    ui_heading '分组管理' page
    ui_status_summary
    ui_section '当前分组'
    py list-ui "$(current)/state.json"
    ui_section '操作'
    ui_item 1 '自动添加希腊名字分组'
    ui_item 2 '修改组显示名称'
    ui_item 3 '离职换密：更换该组密码和订阅链接'
    ui_item 4 '停用分组'
    ui_item 5 '重新启用分组'
    ui_item 6 '删除分组'
    ui_item 7 '选择分组出口：直连 / WARP'
    ui_item 0 '返回主菜单'
    ui_prompt choice '请输入选项编号：' || return 0
    case "$choice" in
        1) group_command add;;
        2) menu_select_group identifier no all; group_command rename "$identifier";;
        3) menu_select_group identifier; group_command rotate "$identifier";;
        4) menu_select_group identifier; group_command disable "$identifier";;
        5) menu_select_group identifier no disabled; group_command enable "$identifier";;
        6) menu_select_group identifier no all; group_command remove "$identifier";;
        7) menu_select_group identifier no all; warp_select_egress egress; group_command egress "$identifier" "$egress";;
        0) return;; *) die '无效选择。';;
    esac
}
diagnose() {
    local d p; d=$(current); p=$(py get "$d/state.json" port)
    "$d/sing-box" version | head -n 1
    systemctl --no-pager --lines=0 status "$SERVICE" || true
    say "管理工具：$MANAGER_VERSION；活跃分组：$(py get "$d/state.json" active_group_count)"
    say "服务器地址：$(py get "$d/state.json" server)，TCP 端口：$p"
    say "当前系统 TCP 拥塞算法：$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || printf unknown)（只读检查，不改变 BBR）"
    ss -lntp "( sport = :$p )"
    openssl x509 -in "$d/server.crt" -noout -dates -fingerprint -sha256
    if ! openssl x509 -in "$d/server.crt" -noout -checkend 2592000; then
        say '提示：证书已过期或不足30天，请续期并重新导入服务器证书。'
        if [[ $(py get "$d/state.json" tls_verify) == pin ]]; then
            say '当前使用固定指纹；换证后客户端还须更新配置。'
        fi
    fi
    if tls_probe "$d"; then say '本机 TLS 检查：通过（已核验证书及 ALPN）。'
    else say '本机 TLS 检查：失败，请运行 any logs。'; fi
    say "公网检查请在另一台电脑运行：Test-NetConnection $(py get "$d/state.json" server) -Port $p"
    say '本机检查成功不代表公网可达；更换协议不会修复 TCP 握手之前的网络丢包。'
}
change_setting() {
    local action=$1 value=${2:-} old oldp
    old=$(current); oldp=$(py get "$old/state.json" port)
    case "$action" in
        port) [[ -n "$value" ]] || read -r -p '新的 TCP 端口：' value
            py validate "$(py get "$old/state.json" server)" "$value" >/dev/null
            if [[ "$value" == "$oldp" ]]; then say '端口没有改变。'; return; fi
            free_port "$value";;
        server) [[ -n "$value" ]] || read -r -p '新的公网 IPv4 或域名：' value;;
        password|certificate) :;;
        *) die '不支持的设置项。';;
    esac
    clone_current
    py edit "$WORK/state.json" "$action" "$value"
    if [[ "$action" == certificate ]]; then py certificate "$WORK"; fi
    finalize_generation; activate "$WORK"
    say '变更已保存。请重新导出并更新客户端配置。'
    show_summary
}
import_certificate() {
    local cert=${1:-} key=${2:-} identity=${3:-} mode=${4:-pki}
    [[ -n "$cert" ]] || read -r -p '证书/完整证书链 PEM 文件的绝对路径：' cert
    [[ -n "$key" ]] || read -r -p '未加密私钥 PEM 文件的绝对路径：' key
    [[ -n "$identity" ]] || read -r -p '证书对应的域名/SNI：' identity
    [[ "$cert" == /* && "$key" == /* && -f "$cert" && -f "$key" ]] || die '证书和私钥必须是已存在文件的绝对路径。'
    clone_current
    cp -L -- "$cert" "$WORK/server.crt"; cp -L -- "$key" "$WORK/server.key"
    py edit "$WORK/state.json" import-cert "$identity" "$mode"
    finalize_generation; activate "$WORK"
    if [[ "$mode" == pki ]]; then
        say '已导入系统信任的域名证书，新导出配置使用正常证书链/域名验证，无固定指纹。'
        say '原来已导入指纹配置的客户端需更新一次配置；未来证书续期后仍需重新导入服务器证书。'
    else
        say '已按固定指纹模式导入证书；换证后客户端必须同步更新指纹。'
    fi
    show_summary
}
update_core() {
    local version=${1:-latest}
    clone_current; fetch_core "$version"; finalize_generation; activate "$WORK"
    say '核心已更新。证书、密码和端口保持原值；上一个版本可用 rollback 恢复。'
}
rollback() {
    local target active; active=$(current)
    [[ -L "$BASE/previous" ]] || die '没有可回滚的上一版本。'
    target=$(readlink -f "$BASE/previous")
    [[ "$target" == "$BASE/releases/"* && -d "$target" && -f "$target/state.json" ]] || die '回滚目标不符合要求。'
    guard_generation "$target"
    # Rebuild the older endpoint/core with CURRENT identities. Revocations are never rolled back.
    new_generation
    cp -- "$target/state.json" "$target/server.crt" "$target/server.key" "$WORK/"
    ln -- "$target/sing-box" "$WORK/sing-box"
    py preserve-identity "$active/state.json" "$WORK/state.json"
    finalize_generation; activate "$WORK"
    say '核心/端口/证书已回滚；分组、现有密码、订阅链接和停用状态保留，已撤销账号不会复活。'
    show_summary
}

uninstall_server() {
    local answer; owned_base
    read -r -p '输入 REMOVE 确认停用并删除本工具的服务/管理命令（配置备份保留）：' answer
    [[ "$answer" == REMOVE ]] || { say '已取消。'; return; }
    require_owned_unit
    subscription_stop_for_uninstall
    systemctl disable --now "$SERVICE"
    rm -f -- "$UNIT"
    manager_remove_short_command
    if [[ -f "$MANAGER" && ! -L "$MANAGER" ]] && grep -q 'readonly BASE=/opt/jackie-anytls SERVICE=jackie-anytls.service' "$MANAGER"; then rm -f -- "$MANAGER"; fi
    systemctl daemon-reload
    say "服务已卸载。$BASE 内的配置、密钥和历史版本以及专用无登录用户被保留，避免误删；目录不再对外提供服务。"
    say '要恢复，请用本脚本运行 restore-service。'
}
help_text() {
cat <<'HELP'
AnyHarbor 管理工具 1.7.4（独立 sing-box 服务）
用法：any [命令]；直接输入 any 打开数字菜单
  install                            安装向导：域名与已有可信证书，或IPv4自签测试
  install 公网IPv4或域名 [端口8443]  兼容非交互安装，使用自签证书
  status / diagnose                  查看服务、证书、监听及本机TLS
  export [组ID] [all|clash|v2rayn|shadowrocket] 默认显示支持的格式；指定格式输出原始内容
  export-clash [组ID]                仅输出完整 YAML，适合重定向保存
  export-v2rayn [组ID]               v2rayN 7.22.6+ 单行分享链接（含组密码）
  export-shadowrocket [组ID]         Shadowrocket 单行分享链接（仅可信证书模式）
  groups                             中文分组管理菜单
  add                                自动随机分配希腊名字及组ID，创建一组
  group add [组ID 显示名称]           不填参数自动分配；也可手动指定
  group list|add|rename|rotate|disable|enable|remove [组ID] [名称]
  group egress 组ID direct|warp      切换整组出口，保留凭据；WARP仅支持TCP
  warp                              WARP安装、连接检查及分组出口菜单
  warp setup|check|connect|logs      官方本机代理；不启用整机WARP隧道
  prefix [新前缀]                    查看或设置本机节点名称前缀，默认GZ
  upgrade-manager                    升级管理工具及显示名称，保留现有账号
  update-source [owner/repo或GitHubURL] 查看来源；提供仓库时切换为公开Release下载
  update-source-ssh owner/repo 私钥路径 [分支main] 绑定私有仓库，只读SSH拉取
  update-source-git owner/repo [分支main] 绑定公开仓库，匿名HTTPS拉取
  check-update [稳定版本号]           检查更新；Git来源不填版本，跟随绑定分支
  self-update [稳定版本号]            校验并原地升级；Git来源无需Release或标签
  manager-rollback                   只回退管理代码，保留当前账号与服务
  subscription                       在线订阅菜单（需域名与受信任证书）
  subscription enable [域名] [证书] [私钥] [端口9443]
  sub [组ID]                         显示该组全部订阅格式；省略组ID显示所有启用组
  subscription links [all|clash|v2rayn|shadowrocket] [组ID] 默认支持的格式；单格式CSV
  subscription check [组ID]         实际检查各格式订阅内容；省略时采样一个启用组
  subscription manual               手动配置订阅域名或重新导入续期证书
  subscription refresh|status|off     更新订阅发布格式/检查/停用
  rules                              Clash 默认规则菜单（作用于本机全部分组）
  rules import JSON文件 | show | reset 导入规则数组、查看或恢复内置分流规则
  logs                               查看最近80行服务日志
  restart                            重启并检查服务
  port [新端口]                      修改监听端口
  password                           仅单活跃组时换密码；多组用 group rotate
  server [新地址]                    修改客户端连接地址，保留原SNI和证书
  certificate                        换新自签证书，客户端须更新指纹
  import-cert [证书路径] [私钥路径] [SNI] [pki或pin]  默认验证公信证书
  update [稳定版本或latest]           从官方发布下载并校验更新
  rollback                           回滚核心/端口/证书，保留当前账号与撤销状态
  uninstall                          停用并删除服务，保留数据备份
  restore-service                    从保留的数据恢复服务
无参数启动中文菜单。默认只监听 IPv4 TCP；AnyTLS 的UDP经过TCP隧道。
HELP
}
menu_select_group() {
    local target=$1 allow_all=${2:-no} scope=${3:-enabled} d choice selected
    d=$(current)
    ui_section '选择分组'
    py group-options "$d/state.json" "$scope"
    if [[ "$allow_all" == yes ]]; then ui_item 0 '全部启用分组'; fi
    if ! ui_prompt choice '请输入分组前面的数字：'; then
        die '已取消：输入结束，未输出配置或链接。'
    fi
    if [[ "$allow_all" == yes && "$choice" == 0 ]]; then selected=''
    else selected=$(py group-number "$d/state.json" "$choice" "$scope"); fi
    printf -v "$target" '%s' "$selected"
}
menu_export() {
    local command=$1 identifier
    menu_select_group identifier
    main "$command" "$identifier"
}
menu_ssh_source() {
    local repository key_file branch
    ui_section '绑定私有仓库更新'
    ui_note '每台服务器使用独立的只读 deploy key；这里只填写私钥文件路径，不粘贴内容。'
    ui_note '先将对应公钥添加到 GitHub 仓库 Deploy keys，不勾选 Allow write access。'
    ui_prompt repository 'GitHub 仓库 [JackieSung4ev/AnyHarbor]：' || die '已取消：输入结束。'
    ui_prompt key_file '本机私钥绝对路径 [/root/.ssh/gz-anytls_deploy]：' || die '已取消：输入结束。'
    ui_prompt branch '更新分支 [main]：' || die '已取消：输入结束。'
    main update-source-ssh "${repository:-JackieSung4ev/AnyHarbor}" "${key_file:-/root/.ssh/gz-anytls_deploy}" "${branch:-main}"
}
menu_git_source() {
    local repository branch
    ui_section '绑定公开仓库分支更新'
    ui_note '通过 HTTPS 匿名读取可信仓库；无需 Deploy Key 或 Release。'
    ui_prompt repository 'GitHub 仓库 [JackieSung4ev/AnyHarbor]：' || die '已取消：输入结束。'
    ui_prompt branch '更新分支 [main]：' || die '已取消：输入结束。'
    main update-source-git "${repository:-JackieSung4ev/AnyHarbor}" "${branch:-main}"
}
menu_settings() {
    local choice prefix
    ui_heading '连接与显示设置' page
    ui_section '操作'
    ui_item 1 '修改 AnyTLS 端口'
    ui_item 2 '修改客户端连接地址'
    ui_item 3 '导入 / 更新可信 SSL 证书'
    ui_item 4 '生成新自签证书（客户端需更新）'
    ui_item 5 '修改节点名称前缀'
    ui_item 0 '返回主菜单'
    ui_prompt choice '请输入选项编号：' || return 0
    case "$choice" in
        1) main port;; 2) main server;; 3) main import-cert;; 4) main certificate;;
        5) ui_prompt prefix '新的节点名称前缀（例如 GZ-SV02）：' || return 0
           [[ -n "$prefix" ]] || die '前缀不能为空。'; main prefix "$prefix";;
        0) return;; *) die '无效选择。';;
    esac
}
menu_updates() {
    local choice repository
    ui_heading '更新与回退' page
    ui_section '管理工具与核心'
    ui_item 1 '检查管理工具更新'
    ui_item 2 '更新管理工具'
    ui_item 3 '更新 sing-box 核心'
    ui_item 4 '回退管理工具'
    ui_item 5 '回滚核心、端口或证书'
    ui_section '更新来源（通常只需设置一次）'
    ui_item 6 '绑定私有仓库（SSH Deploy Key）'
    ui_item 7 '绑定公开 Release（会切换更新通道）'
    ui_item 8 '绑定公开仓库分支（HTTPS，无需密钥）'
    ui_item 0 '返回主菜单'
    ui_prompt choice '请输入选项编号：' || return 0
    case "$choice" in
        1) main check-update;; 2) main self-update;; 3) main update;;
        4) main manager-rollback;; 5) main rollback;; 6) menu_ssh_source;;
        7) ui_prompt repository '可信 GitHub 仓库（owner/repo）：' || return 0
           [[ -n "$repository" ]] || die '仓库不能为空。'; main update-source "$repository";;
        8) menu_git_source;;
        0) return;; *) die '无效选择。';;
    esac
}
menu_run() {
    local result=0 _reply runner=$SELF
    if [[ "$SELF" == "$BASE/manager-releases/"*"/anytls-manager.sh" ]]; then
        root_readonly "$MANAGER"
        grep -Fqx "$LAUNCHER_MARK" "$MANAGER" || die '受管启动器标记异常。'
        runner=$MANAGER
    fi
    # A separate shell keeps errexit and the maintenance lock local to one action.
    # Do not call a shell function in an `if`: it disables errexit inside it.
    bash "$runner" "$@" || result=$?
    if ((result != 0)); then
        ui_warn "操作未完成（退出码 $result），请查看上方具体原因。"
    fi
    ui_prompt _reply '按回车返回主菜单：' || return 0
    if [[ "$runner" == "$MANAGER" && -f "$MANAGER" && -L "$MANAGER_CURRENT" &&
          $(readlink -f -- "$MANAGER_CURRENT") != "$(dirname -- "$SELF")" ]]; then
        exec bash "$MANAGER"
    fi
}
menu() {
    local choice error=''
    while :; do
        ui_heading "$APP_NAME $MANAGER_VERSION · 主菜单" page
        ui_status_summary
        if [[ -n "$error" ]]; then
            ui_warn "$error"
            error=''
        fi
        ui_section '常用操作'
        ui_item 1 '服务状态与连接检查'
        ui_item 2 '导出节点（选组后显示全部格式）'
        ui_item 3 '订阅管理与链接分发'
        ui_item 4 '分组管理（新增、换密、停用）'
        ui_item 5 '连接、证书与名称设置'
        ui_item 6 '更新与回退'
        ui_item 7 '查看服务日志'
        ui_item 8 '重启代理服务'
        ui_item 11 'Cloudflare WARP 出口'
        ui_section '安装与卸载'
        ui_item 9 '首次安装向导'
        ui_item 10 '卸载服务（保留配置备份）'
        ui_section '退出'
        ui_item 0 '退出'
        ui_prompt choice '请输入选项编号：' || return 0
        case "$choice" in
            1) menu_run diagnose;; 2) menu_run __menu-export;;
            3) menu_run subscription;; 4) menu_run groups;;
            5) menu_run __menu-settings;; 6) menu_run __menu-updates;;
            7) menu_run logs;; 8) menu_run restart;; 9) menu_run install;;
            11) menu_run warp;;
            10) menu_run uninstall; [[ -f "$MANAGER" ]] || return 0;; 0) return;;
            *) error='无效编号，请重新选择。';;
        esac
    done
}
main() {
    local command=${1:-menu}; shift || true
    case "$command" in help|-h|--help) help_text; return;; esac
    root_and_tools
    if [[ "$command" == menu ]]; then menu; return; fi
    case "$command" in
        __menu-export) menu_export export; return;;
        __menu-settings) menu_settings; return;;
        __menu-updates) menu_updates; return;;
    esac
    if [[ "$command" == install ]]; then install_server "$@"; return; fi
    owned_base; lock_base
    case "$command" in
        status|diagnose) diagnose;; export) show_export "$@";; export-v2rayn) show_v2rayn_export "$@";;
        export-clash) show_clash_export "$@";;
        export-shadowrocket) show_shadowrocket_export "$@";;
        groups) group_menu;; group) group_command "$@";;
        warp) warp_command "$@";;
        add) (($# == 0)) || die '用法：any add；手动命名请用 any group add 组ID 显示名称。'; group_command add;;
        prefix) prefix_command "$@";;
        subscription) subscription_command "$@";;
        rules) rules_command "$@";;
        sub) (($# <= 1)) || die '用法：sub [组ID]'; subscription_links all "${1:-}";;
        upgrade-manager) upgrade_manager;;
        update-source) updater source "$BASE" "$@";;
        update-source-git) updater git-source "$BASE" "$@";;
        update-source-ssh) updater ssh-source "$BASE" "$@";; check-update) manager_check_update "$@";;
        self-update) manager_self_update "$@";; manager-rollback) manager_rollback;;
        __manager-commit) manager_commit_worker "$@";; __manager-restore) manager_restore_worker "$@";;
        __manager-code-only) manager_code_rollback_worker "$@";;
        __prefix-commit) prefix_commit_worker "$@";;
        __rules-commit) rules_commit_worker "$@";;
        logs) journalctl -u "$SERVICE" -n 80 --no-pager;;
        restart) current >/dev/null; require_owned_unit; systemctl restart "$SERVICE"; healthy "$(current)" || die '重启后检查失败，请查看日志。'; say '重启及本机 TLS 检查通过。';;
        port|password|certificate|server) change_setting "$command" "$@";;
        import-cert) import_certificate "$@";; update) update_core "$@";; rollback) rollback;;
        uninstall) uninstall_server;;
        restore-service) current >/dev/null; write_unit; install_manager; systemctl enable "$SERVICE"; systemctl restart "$SERVICE"; healthy "$(current)" || die '恢复服务检查失败。'; subscription_restore_if_configured; say '服务已恢复。';;
        *) help_text; die '未知命令。';;
    esac
}
# Load only the local, shipped module.
if [[ ! -f "$HELPER_DIR/anytls-subscription.sh" ]]; then die "缺少配套文件 anytls-subscription.sh，请上传整个解压目录。"; fi
root_readonly "$HELPER_DIR"
root_readonly "$HELPER_DIR/anytls-state.py"
root_readonly "$HELPER_DIR/anytls-subscription.sh"
root_readonly "$HELPER_DIR/anytls-runtime.sh"
root_readonly "$HELPER_DIR/anytls-update.py"
source "$HELPER_DIR/anytls-subscription.sh"
source "$HELPER_DIR/anytls-runtime.sh"
main "$@"
