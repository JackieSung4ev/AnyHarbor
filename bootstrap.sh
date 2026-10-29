#!/usr/bin/env bash
# Download the public source in full before entering the interactive installer.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
ARGS=()
case "${1:-}" in
    -h|--help)
        printf '%s\n' 'AnyHarbor 在线安装入口（Debian + systemd，root）' \
            '不带参数安装；--upgrade 更新已有安装。日常管理运行 any。'
        exit 0 ;;
    '') ;;
    --upgrade) ARGS=(--upgrade) ;;
    *) die '不支持该参数；使用 --help 查看用法。' ;;
esac
[[ $# -le 1 ]] || die '仅接受 --upgrade 或 --help。'
[[ $EUID -eq 0 ]] || die '请使用 root 运行。'
[[ $(uname -s) == Linux ]] && grep -Eq '^ID="?debian"?$' /etc/os-release || die '仅支持 Debian Linux。'
[[ -d /run/systemd/system ]] && command -v systemctl >/dev/null && \
    systemctl show --property=Version --value >/dev/null || die '需要运行中的 systemd。'
for directory in / /opt; do
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || die "目录必须由 root 管理：$directory"
    (( (8#$(stat -c %a "$directory") & 0022) == 0 )) || die "目录不能允许其他用户写入：$directory"
done
if ((${#ARGS[@]} == 0)); then
    [[ ! -e /opt/jackie-anytls && ! -L /opt/jackie-anytls ]] || die '检测到已有安装；运行 any self-update，或使用 --upgrade。'
else
    [[ -d /opt/jackie-anytls && ! -L /opt/jackie-anytls ]] || die '--upgrade 需要已有受管安装。'
fi

PACKAGES=()
for command in git python3; do command -v "$command" >/dev/null || PACKAGES+=("$command"); done
if [[ $(dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null || true) != 'install ok installed' ]]; then
    PACKAGES+=(ca-certificates)
fi
if ((${#PACKAGES[@]})); then
    printf '安装必要工具：%s\n' "${PACKAGES[*]}"
    apt-get update </dev/null
    apt-get install -y -- "${PACKAGES[@]}" </dev/null
fi

WORK=$(mktemp -d /opt/AnyHarbor-source.XXXXXXXX)
trap 'printf "安装停止；下载目录保留在 %s，请保留上方错误输出。\n" "$WORK" >&2' ERR
printf '下载 AnyHarbor：%s\n' "$WORK"
env -i HOME="$WORK" PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=https \
    git -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
    -c credential.helper= -c http.sslVerify=true -c http.followRedirects=false -c http.proxy= \
    -c fetch.fsckObjects=true -c transfer.fsckObjects=true \
    clone --depth 1 --single-branch --branch main --no-tags --no-recurse-submodules --template= \
    https://github.com/JackieSung4ev/AnyHarbor.git "$WORK/source" </dev/null
# A failed clone cannot execute a partial checkout. This process inherits stdin.
[[ -f "$WORK/source/install.sh" && ! -L "$WORK/source/install.sh" ]] || die '下载的源码缺少普通安装入口文件。'
bash "$WORK/source/install.sh" "${ARGS[@]}"
