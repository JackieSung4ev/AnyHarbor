#!/usr/bin/env bash
# Install or update from a trusted checkout; release packaging stays internal.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
OPERATION=install
for argument in "$@"; do
case "$argument" in
    -h|--help)
        printf '%s\n' 'AnyHarbor 安装入口（Debian + systemd，使用 root 运行）' \
            '首次安装：在源码目录运行 bash ./install.sh' \
            '更新已有安装：bash ./install.sh --upgrade。' \
            '自动检查依赖、构建并校验安装包；仅首次安装询问域名、证书、端口等。' \
            '使用匿名 Git HTTPS 更新，无需 GitHub 账号、SSH 配置或 Deploy Key。' \
            '安装完成后运行 any；日常更新运行 any self-update。'
        exit 0 ;;
    --upgrade)
        [[ $OPERATION == install ]] || die '--upgrade 不能重复。'
        OPERATION=upgrade-manager ;;
    *) die '不支持该参数；使用 --help 查看用法。' ;;
esac
done
[[ $EUID -eq 0 ]] || die '请在 Debian 服务器上使用 root 运行。'
if [[ $(uname -s) != Linux ]] || ! grep -Eq '^ID="?debian"?$' /etc/os-release; then
    die '本入口仅支持 Debian Linux。'
fi
if [[ $OPERATION == install ]]; then
    [[ ! -e /opt/jackie-anytls && ! -L /opt/jackie-anytls ]] ||
        die '检测到已有安装；请使用 any self-update，或运行 bash ./install.sh --upgrade，不要重新安装或删除数据。'
else
    [[ -d /opt/jackie-anytls && ! -L /opt/jackie-anytls ]] ||
        die '--upgrade 需要已有受管安装；当前目录缺失或异常，不会改为首次安装。'
fi

# Check the original path before resolving it, including every ancestor.
trust_path() {
    local path=$1 kind=$2
    if [[ $kind == file ]]; then [[ -f $path ]] || die "缺少普通文件：$path"
    else [[ -d $path ]] || die "缺少目录：$path"; fi
    while :; do
        [[ ! -L $path && $(stat -c %u -- "$path") == 0 ]] || die "路径必须属于 root 且不能是软链接：$path"
        (( (8#$(stat -c %a -- "$path") & 0022) == 0 )) || die "路径不能允许其他用户写入：$path"
        [[ $path == / ]] && break
        path=$(dirname -- "$path")
        [[ -d $path ]] || die "祖先路径不是目录：$path"
    done
}
SOURCE=${BASH_SOURCE[0]}
[[ $SOURCE == /* ]] || SOURCE=$PWD/$SOURCE
trust_path "$SOURCE" file
ROOT=$(dirname -- "$SOURCE")
trust_path "$ROOT/tools/build_release.py" file
FILES=(anytls-manager.sh anytls-state.py anytls-subscription.sh anytls-runtime.sh
       anytls-update.py README.txt SOURCES.txt TEST-RESULTS.txt)
for name in "${FILES[@]}"; do trust_path "$ROOT/src/$name" file; done
trust_path /opt directory
if [[ $OPERATION == upgrade-manager ]]; then
    trust_path /opt/jackie-anytls directory
    trust_path /opt/jackie-anytls/.owner file
    [[ $(cat /opt/jackie-anytls/.owner) == jackie-anytls-manager-v1 ]] ||
        die '安装目录的归属标记不符合要求，拒绝更新。'
    trust_path /usr/local/sbin/jackie-anytls file
    if ! grep -Fqx '# Managed by gz-anytls-launcher-v1' /usr/local/sbin/jackie-anytls &&
       ! grep -Fq 'readonly BASE=/opt/jackie-anytls SERVICE=jackie-anytls.service' /usr/local/sbin/jackie-anytls; then
        die '管理命令不属于本工具，拒绝更新。'
    fi
fi
if [[ ! -d /run/systemd/system ]] || ! command -v systemctl >/dev/null ||
    ! systemctl show --property=Version --value >/dev/null; then
    die '未检测到运行中的 systemd；普通容器不支持安装。'
fi
for command in python3 git; do
    command -v "$command" >/dev/null || die '缺少依赖：apt-get update && apt-get install -y python3 git ca-certificates'
done

PACKAGES=()
for pair in curl:curl openssl:openssl ss:iproute2 flock:util-linux useradd:passwd getent:libc-bin; do
    command -v "${pair%%:*}" >/dev/null || PACKAGES+=("${pair#*:}")
done
if [[ $(dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null || true) != 'install ok installed' ]]; then
    PACKAGES+=(ca-certificates)
fi
if ((${#PACKAGES[@]})); then
    printf '通过系统 APT 安装缺少的依赖：%s\n' "${PACKAGES[*]}"
    apt-get update </dev/null
    apt-get install -y -- "${PACKAGES[@]}" </dev/null
fi

WORK=$(mktemp -d /opt/gz-anytls-install.XXXXXXXX)
PHASE='构建并校验安装包'
trap 'printf "流程停止（%s）；构建文件保留在 %s，请保留上方错误输出。\n" "$PHASE" "$WORK" >&2' ERR
printf '构建并校验安装包：%s\n' "$WORK"
python3 -I "$ROOT/tools/build_release.py" --root "$ROOT" --output-dir "$WORK/dist" > "$WORK/build.json"
python3 -I - "$ROOT" "$WORK" <<'PY'
import json, runpy, sys
from pathlib import Path
root, work = map(Path, sys.argv[1:])
helper = runpy.run_path(str(root / 'src/anytls-update.py'))
result = json.loads((work / 'build.json').read_text(encoding='utf-8'))
helper['unpack'](Path(result['archive']), work / 'package',
                 {'digest': result['sha256'], 'version': result['version']}, None)
print('安装包清单、SHA256 和脚本语法检查通过。')
PY

# A separate, unconditional process preserves both errexit and interactive stdin.
if [[ $OPERATION == upgrade-manager ]]; then PHASE='升级管理工具'
else PHASE='首次安装'; fi
bash "$WORK/package/anytls-manager.sh" "$OPERATION"
if [[ $OPERATION == upgrade-manager ]]; then PHASE='管理工具已升级，绑定 Git HTTPS 更新源'
else PHASE='安装已完成，绑定 Git HTTPS 更新源'; fi
/usr/local/sbin/any update-source-git JackieSung4ev/AnyHarbor main
if [[ $OPERATION == upgrade-manager ]]; then PHASE='管理工具已升级且更新源已绑定，检查状态'
else PHASE='安装已完成且更新源已绑定，检查状态'; fi
/usr/local/sbin/any status
if [[ $OPERATION == upgrade-manager ]]; then
    printf '\n更新完成。以后运行 any；更新运行 any self-update。\n'
    printf '%s\n' '已开启订阅时，可运行 any subscription refresh 发布新格式；本次未自动刷新订阅。'
else
    printf '\n安装完成。以后运行 any；更新运行 any self-update。\n'
fi
