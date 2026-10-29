#!/usr/bin/env bash
# Sourced locally by the manager. Code bundles are immutable after promotion.
readonly MANAGER_RELEASES="$BASE/manager-releases" MANAGER_CURRENT="$BASE/manager-current"
readonly MANAGER_PREVIOUS="$BASE/manager-previous" MANAGER_TRANSACTIONS="$BASE/manager-transactions"
readonly LAUNCHER_MARK='# Managed by gz-anytls-launcher-v1'
readonly -a MANAGER_CODE=(anytls-manager.sh anytls-state.py anytls-subscription.sh anytls-runtime.sh anytls-update.py)
updater() { python3 "$HELPER_DIR/anytls-update.py" "$@"; }

# Optional official WARP client. No WARP command runs during a normal upgrade.
# Keep this module in the existing eight-file update contract.
warp_owned() {
    [[ -f "$BASE/.warp-owner" && ! -L "$BASE/.warp-owner" ]] || return 1
    root_readonly "$BASE/.warp-owner"
    grep -Eq '^anyharbor-warp-v1:(prepared|installed|registering|registered)$' "$BASE/.warp-owner"
}
warp_no_mdm() {
    [[ ! -e /var/lib/cloudflare-warp/mdm.xml && ! -L /var/lib/cloudflare-warp/mdm.xml ]] ||
        die '检测到 WARP MDM 管理策略，未修改；请由该策略的管理员管理客户端。'
}
warp_cli() {
    [[ -x /usr/bin/warp-cli ]] || die '未找到官方 /usr/bin/warp-cli，请先运行 any warp setup。'
    root_readonly /usr/bin/warp-cli
    # The owner marker is only created after the local user explicitly accepts
    # Cloudflare's terms. Never silently accept terms for an existing client.
    warp_owned || die '此 WARP 客户端不由 AnyHarbor 管理，未修改它。'
    timeout 30 /usr/bin/warp-cli --accept-tos --no-ansi --no-paginate "$@"
}
warp_listener_check() {
    local listeners
    listeners=$(ss -H -lntp '( sport = :40000 )') || return 1
    printf '%s\n' "$listeners" | python3 -c '
import sys
rows = [line.split() for line in sys.stdin if line.strip()]
ok = bool(rows) and all(len(row) >= 6 and row[3] == "127.0.0.1:40000"
                       and "\"warp-svc\"" in " ".join(row[5:]) for row in rows)
sys.exit(0 if ok else 1)
'
}
warp_check() {
    [[ -x /usr/bin/warp-cli ]] || { say 'WARP：未安装官方客户端。'; return 1; }
    systemctl is-active --quiet warp-svc.service || { say 'WARP：warp-svc 未运行。'; return 1; }
    warp_listener_check || { say 'WARP：未检测到仅监听 127.0.0.1:40000 的 warp-svc 代理。'; return 1; }
    local trace
    # -q ignores curlrc; empty noproxy prevents a pre-existing NO_PROXY from
    # bypassing SOCKS. socks5-hostname keeps this DNS lookup inside the proxy.
    trace=$(curl -q --fail --silent --show-error --noproxy '' \
        --proxy socks5h://127.0.0.1:40000 --proto '=https' \
        --connect-timeout 10 --max-time 20 --max-filesize 8192 \
        https://www.cloudflare.com/cdn-cgi/trace) || { say 'WARP：经本机 SOCKS 的 HTTPS 检查失败。'; return 1; }
    if ! printf '%s\n' "$trace" | grep -Eq $'^warp=(on|plus)\r?$'; then
        say 'WARP：Cloudflare 未确认本次请求经过 WARP，不能用于分组。'; return 1
    fi
    say 'WARP：本机代理及 HTTPS 出口检查通过（warp=on/plus）。'
    say '这不代表 Grok 等目标网站放行；本功能仅支持 TCP，客户端自身的 DNS 不受此检查覆盖。'
}
warp_require_ready() {
    warp_check || die '未切换分组出口。请先在 any → 11 中完成 WARP 设置与检查。'
}
warp_set_proxy() {
    # Check every command: this function may run inside a conditional context.
    # Configure local proxy BEFORE registration/connect, never full-host mode.
    warp_cli disconnect || return 1
    warp_cli mode proxy || return 1
    warp_cli proxy port 40000 || return 1
    warp_cli tunnel protocol set MASQUE || return 1
}
warp_connect() {
    warp_owned || die '已有 WARP 不由本工具管理；仅可运行 any warp check，不自动接管其网络设置。'
    warp_no_mdm
    warp_cli registration show >/dev/null || die '未确认有效 WARP 注册，请先运行 any warp setup。'
    say '正在重连本工具的 WARP 本机代理；已有 WARP 分组会短暂断开。'
    if ! warp_set_proxy; then die '本机代理模式设置失败，未执行 connect。'; fi
    warp_cli connect || die 'WARP connect 失败；分组不会回落直连。'
    warp_wait_ready
}
warp_wait_ready() {
    local attempt
    for ((attempt=0; attempt<4; attempt++)); do
        if warp_check; then return; fi
        if ((attempt < 3)); then sleep 2; fi
    done
    die 'WARP 尚未通过出口检查；未切换任何分组。运行 any warp logs 查看日志后重试。'
}
warp_install_package() {
    local codename source=/etc/apt/sources.list.d/anyharbor-cloudflare-warp.list
    local key=/usr/share/keyrings/anyharbor-cloudflare-warp.gpg staging architecture
    local -a official_apt packages
    # os-release is data, never source an arbitrary shell file as root.
    codename=$(python3 -c '
import shlex
values = {}
with open("/etc/os-release") as stream:
    for line in stream:
        key, sep, value = line.rstrip().partition("=")
        if sep and key in ("ID", "VERSION_ID"):
            values[key] = "".join(shlex.split(value))
if values.get("ID") != "debian" or values.get("VERSION_ID") not in ("12", "13"):
    raise SystemExit("WARP 自动安装仅支持 Debian 12/13。")
print({"12": "bookworm", "13": "trixie"}[values["VERSION_ID"]])') || return 1
    architecture=$(dpkg --print-architecture) || return 1
    case "$architecture" in amd64|arm64) :;; *) die 'WARP 自动安装仅支持 amd64/arm64。';; esac
    root_readonly /etc/apt/sources.list.d; root_readonly /usr/share/keyrings
    # Do not overwrite or repair somebody else's Cloudflare repository/key.
    python3 - "$source" <<'PY' || return 1
from pathlib import Path
import sys
owned = Path(sys.argv[1])
paths = [Path('/etc/apt/sources.list')]
paths += list(Path('/etc/apt/sources.list.d').glob('*.list'))
paths += list(Path('/etc/apt/sources.list.d').glob('*.sources'))
for path in paths:
    if path == owned or not path.is_file():
        continue
    if 'pkg.cloudflareclient.com' in path.read_text():
        raise SystemExit('已有其他 Cloudflare APT 源，请先按官方文档核对；未覆盖它：' + str(path))
PY
    if [[ -e "$source" || -L "$source" ]]; then
        root_readonly "$source"
        grep -Fqx '# Managed by anyharbor-warp-v1' "$source" || die 'WARP 源文件归属未知，未覆盖。'
    fi
    if [[ -e "$key" || -L "$key" ]]; then root_readonly "$key"; fi
    if ! command -v gpg >/dev/null; then
        apt-get update || return 1
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gnupg || return 1
    fi
    staging=$(mktemp -d "$BASE/warp-package-XXXXXXXX") || return 1
    curl -q --fail --silent --show-error --proto '=https' --connect-timeout 15 --max-time 60 \
        --max-filesize 1048576 https://pkg.cloudflareclient.com/pubkey.gpg -o "$staging/pubkey.gpg" || return 1
    gpg --batch --yes --dearmor --output "$staging/keyring.gpg" "$staging/pubkey.gpg" || return 1
    # Fingerprint verified against the official signed package index. Expiry
    # extensions retain this fingerprint; a changed primary key needs review.
    gpg --batch --show-keys --with-colons "$staging/keyring.gpg" | python3 -c '
import sys
primary, fingerprints, waiting = 0, [], False
for line in sys.stdin:
    fields = line.rstrip().split(":")
    if fields[0] == "pub": primary += 1; waiting = True
    elif fields[0] == "fpr" and waiting:
        fingerprints.append(fields[9]); waiting = False
sys.exit(0 if primary == 1 and fingerprints == ["C068A2B5771775193CBE1F2F6E2DD2174FA1C3BA"] else 1)
' || return 1
    install -m 0644 "$staging/keyring.gpg" "$key" || return 1
    printf '# Managed by anyharbor-warp-v1\ndeb [signed-by=%s] https://pkg.cloudflareclient.com/ %s main\n' \
        "$key" "$codename" >"$source" || return 1
    chmod 0644 "$source" || return 1
    # Resolve and download this package against ONLY the signed official index.
    # The ordinary system sources may supply dependencies, never the WARP deb.
    install -d -m 0755 "$staging/lists" "$staging/lists/partial" || return 1
    official_apt=(-o "Dir::Etc::sourcelist=$source" -o Dir::Etc::sourceparts=-
                 -o "Dir::State::lists=$staging/lists" -o Acquire::AllowInsecureRepositories=false
                 -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false)
    apt-get "${official_apt[@]}" update || return 1
    (cd -- "$staging" && apt-get "${official_apt[@]}" download cloudflare-warp) || return 1
    packages=("$staging"/cloudflare-warp_*_"$architecture".deb)
    [[ ${#packages[@]} == 1 && -f "${packages[0]}" && ! -L "${packages[0]}" ]] || return 1
    [[ $(dpkg-deb -f "${packages[0]}" Package) == cloudflare-warp &&
       $(dpkg-deb -f "${packages[0]}" Architecture) == "$architecture" ]] || return 1
    apt-get update || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[0]}" || return 1
    # staging is a fresh root-only directory below the managed BASE, not input.
    rm -rf -- "$staging"
}
warp_setup() {
    local answer stage fresh=0
    warp_no_mdm
    if ! warp_owned; then
        if [[ -e /usr/bin/warp-cli || -e /usr/bin/warp-svc || -e /var/lib/cloudflare-warp ]] ||
           command -v warp-cli >/dev/null || command -v warp-svc >/dev/null ||
           dpkg-query -W -f='${Status}' cloudflare-warp 2>/dev/null | grep -q ' installed' ||
           systemctl cat warp-svc.service >/dev/null 2>&1; then
            say '发现已有 WARP 安装或数据，仅作出口检查，不自动安装、注册或接管。'
            warp_check || die '请先用 Cloudflare 官方客户端配置本机 SOCKS5 127.0.0.1:40000，然后重新检查。'
            return
        fi
        free_port 40000
        ui_heading '启用可选 Cloudflare WARP'
        say '将添加 Cloudflare 官方 APT 源、安装客户端，并注册设备。'
        say '只配置本机代理 127.0.0.1:40000，不启用整机隧道；分组仍需另外选择 WARP。'
        say 'Cloudflare 会处理该出口流量；不保证目标网站可用。'
        say '条款：https://www.cloudflare.com/application/terms/'
        say '隐私：https://www.cloudflare.com/application/privacypolicy/'
        IFS= read -r -p '阅读并同意上述条款及安装操作后输入 WARP；其他输入取消：' answer || return 0
        [[ "$answer" == WARP ]] || { say '已取消，未安装或注册。'; return; }
        if [[ -e "$BASE/.warp-owner" || -L "$BASE/.warp-owner" ]]; then die 'WARP 归属记录异常，未覆盖。'; fi
        printf 'anyharbor-warp-v1:prepared\n' >"$BASE/.warp-owner"
    fi
    stage=$(cat "$BASE/.warp-owner")
    if [[ "$stage" == anyharbor-warp-v1:prepared ]] &&
       [[ -e /usr/bin/warp-cli || -e /usr/bin/warp-svc || -e /var/lib/cloudflare-warp ]]; then
        die '上次安装未确认完成，但已有 WARP 程序或数据；未自动接管，请先人工核对安装结果。'
    fi
    if [[ ! -x /usr/bin/warp-cli ]]; then
        [[ "$stage" == anyharbor-warp-v1:prepared ]] || die '已有 WARP 注册记录但程序缺失，未重新安装或注册。'
        warp_install_package || die '官方 WARP 软件包安装失败；未切换分组，保留安装记录以便排查。'
        printf 'anyharbor-warp-v1:installed\n' >"$BASE/.warp-owner"
        stage=anyharbor-warp-v1:installed
    fi
    warp_no_mdm
    systemctl enable --now warp-svc.service || die 'WARP 服务启动失败，未执行注册或连接。'
    if [[ "$stage" == anyharbor-warp-v1:installed ]]; then fresh=1
    elif ! warp_cli registration show >/dev/null; then
        die '上次注册未确认完成；未重复注册。检查 any warp logs，按官方说明完成注册后重新运行 setup。'
    fi
    if ! warp_set_proxy; then die '本机代理模式设置失败，未注册或连接。'; fi
    if ((fresh)); then
        printf 'anyharbor-warp-v1:registering\n' >"$BASE/.warp-owner"
        warp_cli registration new || die 'WARP 注册失败；未连接或切换分组，请查看官方客户端错误。'
        # Do not assume a new registration preserves local preferences.
        if ! warp_set_proxy; then die '注册后无法确认本机代理设置，未执行 connect。'; fi
    fi
    printf 'anyharbor-warp-v1:registered\n' >"$BASE/.warp-owner"
    warp_cli connect || die 'WARP connect 失败；未切换分组。'
    warp_wait_ready
    say 'WARP 准备完成。运行 any → 4 → 7 选择分组出口；现有分组仍按原设置连接。'
}
warp_select_egress() {
    local target=$1 answer selected
    ui_section '分组出口（同组所有成员共用）'
    ui_item 1 '直连：服务器公网出口（默认）'
    ui_item 2 'Cloudflare WARP：仅 TCP，断线阻断，不回落直连'
    IFS= read -r -p '请输入编号 [1]：' answer || die '已取消，未修改分组。'
    case "${answer:-1}" in 1) selected=direct;; 2) selected=warp;; *) die '无效出口编号。';; esac
    printf -v "$target" '%s' "$selected"
}
warp_command() {
    local action=${1:-menu} choice identifier egress
    (($# <= 1)) || die '用法：any warp [setup|check|connect|logs]'
    case "$action" in
        setup) warp_setup;;
        check) warp_check;;
        connect) warp_connect;;
        logs) journalctl -u warp-svc.service -n 60 --no-pager;;
        menu)
            ui_heading 'Cloudflare WARP · 本机代理出口'
            ui_note "启用的 WARP 分组：$(py get "$(current)/state.json" active_warp_group_count)"
            ui_item 1 '安装并设置官方 WARP（首次需要同意 Cloudflare 条款）'
            ui_item 2 '检查本机代理与实际 HTTPS 出口'
            ui_item 3 '选择分组出口：直连 / WARP'
            ui_item 4 '重连本工具管理的 WARP'
            ui_item 5 '查看 WARP 服务日志'
            ui_item 0 '返回主菜单'
            IFS= read -r -p '请输入选项编号：' choice || return 0
            case "$choice" in
                1) warp_setup;; 2) warp_check;;
                3) menu_select_group identifier no all; warp_select_egress egress; group_command egress "$identifier" "$egress";;
                4) warp_connect;; 5) journalctl -u warp-svc.service -n 60 --no-pager;;
                0) return;; *) die '无效选择。';;
            esac;;
        *) die '用法：any warp [setup|check|connect|logs]';;
    esac
}

manager_roots() {
    local directory
    for directory in "$MANAGER_RELEASES" "$MANAGER_TRANSACTIONS"; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            [[ -d "$directory" ]] || die "管理器目录类型错误：$directory"
            root_readonly "$directory"
        else
            install -d -m 0700 -- "$directory"
        fi
    done
}

manager_bundle_guard() {
    local directory=$1 file
    [[ $(dirname -- "$directory") == "$MANAGER_RELEASES" && -d "$directory" ]] || die '管理器版本目录越界。'
    root_readonly "$MANAGER_RELEASES"; root_readonly "$directory"
    if [[ -f "$directory/.legacy" ]]; then
        root_readonly "$directory/.legacy"
        for file in anytls-manager.sh anytls-state.py anytls-subscription.sh; do
            [[ -f "$directory/$file" ]] || die "旧管理器缺少文件：$file"
            root_readonly "$directory/$file"
        done
    else
        for file in "${MANAGER_CODE[@]}" manifest.json; do
            [[ -f "$directory/$file" ]] || die "管理器缺少文件：$file"
            root_readonly "$directory/$file"
        done
    fi
}

manager_pointer() {
    local link=$1 directory
    [[ "$link" == "$MANAGER_CURRENT" || "$link" == "$MANAGER_PREVIOUS" ]] || die '不支持的管理器指针。'
    [[ -L "$link" && $(stat -c %u -- "$link") == 0 ]] || die "管理器指针不是受管软链接：$link"
    directory=$(readlink -f -- "$link")
    manager_bundle_guard "$directory"
    printf '%s\n' "$directory"
}

manager_short_command_owned() {
    [[ -L "$SHORT_MANAGER" && $(stat -c %u -- "$SHORT_MANAGER") == 0 &&
       $(readlink -- "$SHORT_MANAGER") == "$MANAGER" ]]
}

manager_short_command_guard() {
    local candidate
    [[ "$SHORT_MANAGER" == /* && "$SHORT_MANAGER" != "$MANAGER" ]] || die '短命令路径配置无效。'
    root_readonly "$(dirname -- "$SHORT_MANAGER")"
    if [[ -e "$SHORT_MANAGER" || -L "$SHORT_MANAGER" ]]; then
        manager_short_command_owned || die "短命令路径已被占用或归属异常，拒绝覆盖：$SHORT_MANAGER"
    fi
    while IFS= read -r candidate; do
        [[ "$candidate" != "$SHORT_MANAGER" ]] || continue
        if [[ ! -L "$candidate" || $(stat -c %u -- "$candidate") != 0 ||
              $(readlink -- "$candidate") != "$MANAGER" ]]; then
            die "PATH 中已有同名命令，未覆盖或改动它：$candidate"
        fi
    done < <(PATH="/usr/local/sbin:/usr/local/bin:$PATH" type -a -p -- "${SHORT_MANAGER##*/}" || true)
}

manager_install_short_command() {
    manager_short_command_guard
    if manager_short_command_owned; then return; fi
    ln -s -- "$MANAGER" "$SHORT_MANAGER" || die "无法创建短命令：$SHORT_MANAGER"
}

manager_remove_short_command() {
    if [[ ! -e "$SHORT_MANAGER" && ! -L "$SHORT_MANAGER" ]]; then return; fi
    root_readonly "$(dirname -- "$SHORT_MANAGER")"
    if ! manager_short_command_owned; then
        printf '短命令路径不是本工具管理的链接，已保留：%s\n' "$SHORT_MANAGER" >&2
        return
    fi
    rm -f -- "$SHORT_MANAGER"
}

manager_restore_short_command() {
    local transaction=$1 marker="$1/short-command-state" previous
    # Older transactions predate the short command and must not remove it.
    if [[ ! -e "$marker" && ! -L "$marker" ]]; then return; fi
    [[ -f "$marker" ]] || die '短命令事务记录不是普通文件。'
    root_readonly "$marker"
    previous=$(cat "$marker")
    case "$previous" in
        present) manager_install_short_command;;
        absent)
            manager_short_command_guard
            manager_remove_short_command;;
        *) die "短命令事务记录无效：$transaction";;
    esac
}

manager_target_guard() {
    manager_short_command_guard
    if [[ -e "$MANAGER" || -L "$MANAGER" ]]; then
        [[ -f "$MANAGER" && ! -L "$MANAGER" ]] || die '管理命令不是常规文件，拒绝覆盖。'
        root_readonly "$MANAGER"
        if ! grep -Fqx "$LAUNCHER_MARK" "$MANAGER" &&
           ! grep -Fq 'readonly BASE=/opt/jackie-anytls SERVICE=jackie-anytls.service' "$MANAGER"; then
            die '管理命令路径被其他程序占用。'
        fi
    fi
    local pointer
    for pointer in "$MANAGER_CURRENT" "$MANAGER_PREVIOUS"; do
        if [[ -e "$pointer" || -L "$pointer" ]]; then manager_pointer "$pointer" >/dev/null; fi
    done
}

manager_legacy_bundle() {
    local directory file
    [[ -f "$MANAGER" ]] || die '没有可备份的旧管理器。'
    root_readonly "$BASE/lib"
    for file in anytls-state.py anytls-subscription.sh; do root_readonly "$BASE/lib/$file"; done
    directory=$(mktemp -d "$MANAGER_RELEASES/legacy-XXXXXXXX")
    install -m 0755 -- "$MANAGER" "$directory/anytls-manager.sh"
    for file in anytls-state.py anytls-subscription.sh; do install -m 0644 -- "$BASE/lib/$file" "$directory/$file"; done
    printf '%s\n' 'Trusted installed three-file manager backup' >"$directory/.legacy"
    manager_bundle_guard "$directory"
    printf '%s\n' "$directory"
}

manager_active_bundle() {
    # A first transition preserves the complete old three-file installation.
    if [[ -f "$MANAGER" ]] && ! grep -Fqx "$LAUNCHER_MARK" "$MANAGER"; then
        manager_legacy_bundle
    elif [[ -L "$MANAGER_CURRENT" ]]; then
        manager_pointer "$MANAGER_CURRENT"
    elif [[ -f "$MANAGER" ]]; then
        die '受管启动器缺少 manager-current 指针。'
    fi
}

manager_prepare_bundle() {
    local directory file active=''
    root_readonly "$HELPER_DIR"
    updater verify "$HELPER_DIR" "$MANAGER_VERSION" >/dev/null
    if [[ -L "$MANAGER_CURRENT" ]]; then
        active=$(manager_pointer "$MANAGER_CURRENT")
        if [[ ! -f "$active/.legacy" ]] && cmp -s -- "$active/manifest.json" "$HELPER_DIR/manifest.json"; then
            updater verify "$active" "$MANAGER_VERSION" >/dev/null
            printf '%s\n' "$active"
            return
        fi
    fi
    directory=$(mktemp -d "$MANAGER_RELEASES/manager-$MANAGER_VERSION-XXXXXXXX")
    for file in "${MANAGER_CODE[@]}" README.txt SOURCES.txt TEST-RESULTS.txt manifest.json SHA256SUMS.txt; do
        [[ -f "$HELPER_DIR/$file" ]] || die "缺少完整发行包文件：$file"
        root_readonly "$HELPER_DIR/$file"
        install -m 0644 -- "$HELPER_DIR/$file" "$directory/$file"
    done
    chmod 0755 "$directory/anytls-manager.sh"
    updater verify "$directory" "$MANAGER_VERSION" >/dev/null
    manager_bundle_guard "$directory"
    printf '%s\n' "$directory"
}

manager_write_launcher() {
    local temporary
    manager_target_guard
    if [[ -f "$MANAGER" ]] && grep -Fqx "$LAUNCHER_MARK" "$MANAGER"; then return; fi
    temporary=$(mktemp /usr/local/sbin/.gz-anytls-launcher-XXXXXXXX)
    cat >"$temporary" <<'LAUNCHER'
#!/usr/bin/env bash
# Managed by gz-anytls-launcher-v1
set -euo pipefail
readonly BASE=/opt/jackie-anytls SERVICE=jackie-anytls.service
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || fail '请使用 sudo any。'
safe() {
    [[ -e "$1" && ! -L "$1" && $(stat -c %u -- "$1") == 0 ]] || fail "路径归属异常：$1"
    (( (8#$(stat -c %a -- "$1") & 0022) == 0 )) || fail "路径可被非root修改：$1"
}
safe "$BASE"; safe "$BASE/manager-releases"
[[ -L "$BASE/manager-current" && $(stat -c %u -- "$BASE/manager-current") == 0 ]] || fail '管理器版本指针异常。'
directory=$(readlink -f -- "$BASE/manager-current")
[[ $(dirname -- "$directory") == "$BASE/manager-releases" && -d "$directory" ]] || fail '管理器版本目录越界。'
safe "$directory"
files=(anytls-manager.sh anytls-state.py anytls-subscription.sh)
if [[ -f "$directory/.legacy" ]]; then safe "$directory/.legacy"
else files+=(anytls-runtime.sh anytls-update.py manifest.json); fi
for file in "${files[@]}"; do [[ -f "$directory/$file" ]] || fail "缺少文件：$file"; safe "$directory/$file"; done
# Resolve once, before exec, so code and helpers always come from one bundle.
exec bash "$directory/anytls-manager.sh" "$@"
LAUNCHER
    chmod 0755 "$temporary"
    mv -Tf -- "$temporary" "$MANAGER"
}

manager_switch_bundle() {
    local next=$1 old=${2:-}
    manager_target_guard
    manager_bundle_guard "$next"
    if [[ -n "$old" && "$old" != "$next" ]]; then
        manager_bundle_guard "$old"
        atomic_link "$old" "$MANAGER_PREVIOUS"
    fi
    atomic_link "$next" "$MANAGER_CURRENT"
    manager_write_launcher
    manager_install_short_command
}

install_manager() {
    manager_roots; manager_target_guard
    local old next
    old=$(manager_active_bundle)
    next=$(manager_prepare_bundle)
    manager_switch_bundle "$next" "$old"
}

manager_snapshot() {
    local old_bundle=$1 directory pointer value
    manager_short_command_guard
    directory=$(mktemp -d "$MANAGER_TRANSACTIONS/transaction-XXXXXXXX")
    printf '%s\n' "$old_bundle" >"$directory/active-bundle"
    for pointer in manager-current manager-previous current previous; do
        value=''
        if [[ -L "$BASE/$pointer" ]]; then value=$(readlink -f -- "$BASE/$pointer"); fi
        printf '%s\n' "$value" >"$directory/$pointer"
    done
    if [[ -f "$MANAGER" ]]; then install -m 0700 -- "$MANAGER" "$directory/launcher.backup"
    else touch "$directory/launcher.absent"; fi
    if manager_short_command_owned; then printf 'present\n' >"$directory/short-command-state"
    else printf 'absent\n' >"$directory/short-command-state"; fi
    if systemctl is-active --quiet "$SERVICE"; then printf 'yes\n' >"$directory/was-active"
    else printf 'no\n' >"$directory/was-active"; fi
    printf '%s\n' "$directory"
}

manager_transaction_guard() {
    local directory=$1 file
    [[ $(dirname -- "$directory") == "$MANAGER_TRANSACTIONS" && -d "$directory" ]] || die '管理器事务目录越界。'
    root_readonly "$MANAGER_TRANSACTIONS"; root_readonly "$directory"
    for file in active-bundle manager-current manager-previous current previous was-active; do root_readonly "$directory/$file"; done
}

manager_exports_equal() {
    python3 - "$1" "$2" "${3:-strict}" <<'PY'
import json, sys
from pathlib import Path
a, b = map(Path, sys.argv[1:3])
mode = sys.argv[3]
if mode not in ('strict', 'rollback'): sys.exit(2)
if json.loads((a/'state.json').read_text()) != json.loads((b/'state.json').read_text()):
    sys.exit(1)
for name in ('profiles','nodes','subscriptions','v2rayn','subscriptions_v2rayn',
             'shadowrocket','subscriptions_shadowrocket'):
    # Older renderers do not know these formats. Code-only rollback retains
    # current data; compare all formats the target can render, plus all legacy
    # formats. Upgrade equality stays strict so new exports are published.
    target = b/name
    if (mode == 'rollback' and name in ('shadowrocket', 'subscriptions_shadowrocket')
            and not target.exists() and not target.is_symlink()):
        continue
    def contents(root):
        directory = root/name
        if not directory.is_dir(): return None
        return {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file() and not p.is_symlink()}
    if contents(a) != contents(b): sys.exit(1)
for name in ('mihomo-node.yaml','mihomo-profile.yaml'):
    def optional(root):
        p = root/name
        return p.read_bytes() if p.exists() else None
    if optional(a) != optional(b): sys.exit(1)
PY
}

manager_commit_worker() {
    local transaction=$1 next_bundle=$2 next_data=$3 old_data mode was_active
    manager_transaction_guard "$transaction"; manager_bundle_guard "$next_bundle"; guard_generation "$next_data"
    old_data=$(cat "$transaction/current"); guard_generation "$old_data"
    [[ $(current) == "$old_data" ]] || die '当前数据版本已变化，拒绝应用过期升级。'
    mode=$(updater protect "$old_data" "$next_data")
    [[ "$mode" == same_runtime || "$mode" == changed_runtime ]] || die '无法判断运行配置兼容性。'
    was_active=$(cat "$transaction/was-active")
    manager_switch_bundle "$next_bundle" "$(cat "$transaction/active-bundle")"
    if [[ "$mode" == same_runtime ]] && manager_exports_equal "$old_data" "$next_data"; then
        say '运行配置和导出未变化，仅更新管理代码；代理服务未重启。'
    elif [[ "$mode" == same_runtime || "$was_active" != yes ]]; then
        atomic_link "$old_data" "$BASE/previous"
        atomic_link "$next_data" "$BASE/current"
        say '已更新管理代码和导出，代理服务保持原运行状态。'
    else
        touch "$transaction/core-restarted"
        activate "$next_data"
    fi
    if [[ "$was_active" == yes ]]; then healthy "$(current)" || die '升级后本机TLS检查失败。'; fi
    printf 'complete\n' >"$transaction/status"
}

manager_restore_worker() {
    local transaction=$1 pointer target temporary old_data was_active
    manager_transaction_guard "$transaction"
    for pointer in manager-current manager-previous; do
        target=$(cat "$transaction/$pointer")
        if [[ -n "$target" ]]; then manager_bundle_guard "$target"; atomic_link "$target" "$BASE/$pointer"
        else rm -f -- "$BASE/$pointer"; fi
    done
    for pointer in current previous; do
        target=$(cat "$transaction/$pointer")
        if [[ -n "$target" ]]; then guard_generation "$target"; atomic_link "$target" "$BASE/$pointer"
        else rm -f -- "$BASE/$pointer"; fi
    done
    if [[ -f "$transaction/launcher.backup" ]]; then
        root_readonly "$transaction/launcher.backup"
        temporary=$(mktemp /usr/local/sbin/.gz-anytls-restore-XXXXXXXX)
        install -m 0755 -- "$transaction/launcher.backup" "$temporary"
        mv -Tf -- "$temporary" "$MANAGER"
    elif [[ -f "$transaction/launcher.absent" ]]; then
        root_readonly "$transaction/launcher.absent"; rm -f -- "$MANAGER"
    else die '缺少启动器恢复信息。'; fi
    manager_restore_short_command "$transaction"
    old_data=$(cat "$transaction/current"); was_active=$(cat "$transaction/was-active")
    if [[ -f "$transaction/core-restarted" ]]; then
        if [[ "$was_active" == yes ]]; then systemctl restart "$SERVICE"
        else systemctl stop "$SERVICE"; fi
    fi
    if [[ "$was_active" == yes ]]; then healthy "$old_data" || die '已恢复旧代码与配置，但旧服务健康检查失败。'; fi
    printf 'restored\n' >"$transaction/status"
}

prefix_commit_worker() {
    local transaction=$1 next_data=$2 old_data
    manager_transaction_guard "$transaction"; guard_generation "$next_data"
    old_data=$(cat "$transaction/current"); guard_generation "$old_data"
    [[ $(current) == "$old_data" ]] || die '当前数据版本已变化，拒绝应用过期前缀设置。'
    [[ $(updater protect-prefix "$old_data" "$next_data") == same_runtime ]] || die '前缀设置改变了代理运行配置，已拒绝。'
    atomic_link "$old_data" "$BASE/previous"
    atomic_link "$next_data" "$BASE/current"
    if [[ $(cat "$transaction/was-active") == yes ]]; then healthy "$next_data" || die '前缀设置后本机TLS检查失败。'; fi
    printf 'complete\n' >"$transaction/status"
}

prefix_command() {
    local old_data old_prefix transaction old_bundle
    (($# <= 1)) || die '用法：any prefix [新前缀]'
    old_data=$(current); old_prefix=$(py get "$old_data/state.json" node_prefix)
    if (($# == 0)); then say "$old_prefix"; return; fi
    if [[ "$1" == "$old_prefix" && $(py get "$old_data/state.json" node_name_override_count) == 0 ]]; then
        say "节点前缀没有改变：$old_prefix"; return
    fi
    clone_current; py edit "$WORK/state.json" prefix "$1"; finalize_generation
    [[ $(updater protect-prefix "$old_data" "$WORK") == same_runtime ]] || die '前缀设置改变了代理运行配置，已拒绝。'
    manager_roots; manager_target_guard
    old_bundle=$(manager_active_bundle)
    transaction=$(manager_snapshot "$old_bundle")
    if GZ_ANYTLS_INHERIT_LOCK=1 bash "$SELF" __prefix-commit "$transaction" "$WORK"; then
        say "节点名称前缀已设置为：$1；代理及订阅服务未重启。"
        say '刷新原订阅或重新导入本地配置即可看到新名称；组密码、订阅地址和连接设置不变。'
    else
        if GZ_ANYTLS_INHERIT_LOCK=1 bash "$SELF" __manager-restore "$transaction"; then
            die "前缀设置未生效，原配置已恢复。事务记录：$transaction"
        fi
        die "前缀设置失败且自动恢复不完整，请保留事务记录：$transaction"
    fi
}

upgrade_manager() {
    local old_data old_bundle next_bundle transaction
    old_data=$(current)
    manager_roots; manager_target_guard
    updater verify "$HELPER_DIR" "$MANAGER_VERSION" >/dev/null
    clone_current; py branding "$WORK/state.json"; finalize_generation
    updater protect "$old_data" "$WORK" >/dev/null
    old_bundle=$(manager_active_bundle)
    next_bundle=$(manager_prepare_bundle)
    transaction=$(manager_snapshot "$old_bundle")
    # An external Bash worker has its own errexit context; an `if function`
    # must not disable error checking across the commit's filesystem writes.
    if GZ_ANYTLS_INHERIT_LOCK=1 bash "$SELF" __manager-commit "$transaction" "$next_bundle" "$WORK"; then
        say "管理工具已升级至 $MANAGER_VERSION；账号、密码、证书与订阅地址已通过保留检查。"
        show_summary
    else
        say '管理器升级失败，正在恢复整套管理代码与本次升级前的数据指针……'
        if GZ_ANYTLS_INHERIT_LOCK=1 bash "$SELF" __manager-restore "$transaction"; then
            die "升级未生效，原代码和配置已恢复。事务记录：$transaction"
        fi
        die "自动恢复未全部成功，请保留事务目录并检查服务：$transaction"
    fi
}

manager_rollback() {
    local old_bundle target old_data check_dir transaction
    manager_roots; manager_target_guard
    old_bundle=$(manager_pointer "$MANAGER_CURRENT")
    target=$(manager_pointer "$MANAGER_PREVIOUS")
    old_data=$(current); clone_current; check_dir=$WORK
    python3 "$target/anytls-state.py" render "$check_dir"
    "$check_dir/sing-box" check -c "$check_dir/config.json"
    updater protect "$old_data" "$check_dir" >/dev/null
    if [[ $(py get "$old_data/state.json" node_prefix) != GZ ]] && ! manager_exports_equal "$old_data" "$check_dir" rollback; then
        die '目标管理器不能原样生成当前导出，已拒绝回退以保留自定义前缀；请使用支持本机前缀的兼容版本。'
    fi
    if [[ ! -f "$target/.legacy" ]]; then updater verify "$target" >/dev/null; fi
    transaction=$(manager_snapshot "$old_bundle")
    if ! GZ_ANYTLS_INHERIT_LOCK=1 bash "$SELF" __manager-code-only "$transaction" "$target"; then
        if GZ_ANYTLS_INHERIT_LOCK=1 bash "$SELF" __manager-restore "$transaction"; then
            die '管理代码回退失败，已恢复此次操作前的版本。'
        fi
        die "管理代码回退失败且自动恢复不完整，请保留事务记录：$transaction"
    fi
    say '已回退整套管理代码；代理服务、当前账号、撤销状态与订阅配置未改变。'
    say "恢复此新版可运行：bash $old_bundle/anytls-manager.sh upgrade-manager"
}

manager_code_rollback_worker() {
    local transaction=$1 target=$2
    manager_transaction_guard "$transaction"; manager_bundle_guard "$target"
    manager_switch_bundle "$target" "$(cat "$transaction/active-bundle")"
    bash "$target/anytls-manager.sh" help >/dev/null
    printf 'complete\n' >"$transaction/status"
}

manager_self_update() {
    local wanted=${1:-latest} candidate
    (($# <= 1)) || die '用法：self-update；仅公开Release模式可指定稳定版本号。'
    candidate=$(updater prepare "$BASE" "$MANAGER_VERSION" "$wanted")
    [[ -n "$candidate" ]] || return 0
    root_readonly "$candidate"
    updater verify "$candidate" >/dev/null
    if ! GZ_ANYTLS_INHERIT_LOCK=1 bash "$candidate/anytls-manager.sh" upgrade-manager; then
        die 'GitHub管理器更新失败；请检查上方恢复结果，当前数据未被重新初始化。'
    fi
}

manager_check_update() {
    local version
    (($# <= 1)) || die '用法：check-update；仅公开Release模式可指定稳定版本号。'
    version=$(updater check "$BASE" "$MANAGER_VERSION" "${1:-latest}")
    if [[ -n "$version" ]]; then say "发现管理工具更新 $version；运行 any self-update 应用。"
    else say "当前管理工具 $MANAGER_VERSION 的安装文件无需更新。"; fi
}
