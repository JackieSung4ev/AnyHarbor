# AnyHarbor

[![检查状态](https://github.com/JackieSung4ev/AnyHarbor/actions/workflows/check.yml/badge.svg)](https://github.com/JackieSung4ev/AnyHarbor/actions/workflows/check.yml)

在 Debian 上管理 AnyTLS。安装后输入 **`any`**，按数字完成分组、节点导出、订阅和日常维护。

使用官方 sing-box 核心，每个分组拥有独立密码和订阅链接，支持 Clash / Mihomo、v2rayN 和 Shadowrocket。AnyHarbor 是独立维护工具，并非 sing-box 官方安装器。

**版本：1.7.1** · Debian + systemd · amd64 / arm64 · root 权限

## 安装

准备好以下信息，安装向导会逐项询问：

- **域名**：A 记录直指服务器公网 IPv4。
- **TLS 证书**：有效的完整证书链和私钥文件路径；宝塔用户可接受按域名推导的默认路径。
- **代理端口和节点前缀**：均可自定义；默认 TCP `8443`，不同服务器使用不同前缀。

在服务器 root 终端运行：

```bash
(s=$(curl -q -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 https://raw.githubusercontent.com/JackieSung4ev/AnyHarbor/main/bootstrap.sh) && bash -c "$s")
```

若系统没有 `curl`，先执行 `apt-get update && apt-get install -y curl ca-certificates`。

入口完整下载后才执行，自动检查依赖、获取源码并启动交互向导。安装官方 sing-box 1.14.4，生成 10 个分组并设置开机启动。已有安装使用更新命令，不重复安装。

在云安全组和系统防火墙放行选定的 **TCP 端口**。脚本不申请证书、不修改 DNS 或防火墙；AnyTLS 的 UDP 流量经过 TCP 隧道。无域名时可明确选择自签测试模式，该模式不提供 Shadowrocket 导出和在线订阅快捷启用。

## 日常使用

```bash
any
```

| 菜单 | 操作 |
| --- | --- |
| 1 | 服务状态与连接检查 |
| 2 | 选组并导出全部节点格式 |
| 3 | 启用订阅、分发链接、检查订阅正文 |
| 4 | 新增分组、改名、换密、启停、删除 |
| 5 | 地址、端口、证书与节点前缀 |
| 6 | 更新与回退 |
| 7 / 8 | 查看日志 / 重启服务 |
| 11 | Cloudflare WARP 安装、出口检查与分组选择 |

按数字选组，不需要记住组 ID。快捷命令 `any add` 会自动选择未使用的希腊英文名，最多支持 100 个分组。

## 节点与订阅

选择菜单 **2** 导出节点；选择 **3 → 1** 开启 HTTPS 订阅。域名和可信证书可复用安装时的设置，只需填写独立的订阅端口，默认 `9443`。

订阅服务需要 Nginx；已有宝塔 / Nginx 可复用，未安装时见[订阅配置](docs/operations.md#在线订阅)。启用后通过 **3 → 3** 获取分组链接：

| 客户端 | 选择的格式 | 订阅路径 |
| --- | --- | --- |
| Clash Verge / Mihomo / 支持 AnyTLS 的 FlClash | Clash YAML | `/s/…` |
| 支持 AnyTLS 的 v2rayN | v2rayN | `/v/…` |
| Shadowrocket | Shadowrocket / AnyTLS，需可信证书 | `/r/…` |

```bash
any export athena                 # 查看这个分组的全部节点格式
any sub athena                    # 查看这个分组的全部订阅链接
any subscription check athena     # 检查本机实际发布的订阅正文
```

只复制对应格式的配置或完整 URL，不复制标题。订阅已经编码，不要再次 Base64 编码；Clash YAML 转成 Base64 也不会成为 Shadowrocket 订阅。多台服务器汇总见[操作说明](docs/operations.md#汇总多个服务器)。

## 可选 WARP 出口

默认分组使用服务器直连。需要通过 Cloudflare 出口访问网站时：

1. 输入 `any`，选择 **11 → 1**。阅读并同意 Cloudflare 条款后，安装官方客户端并配置本机 SOCKS 代理。
2. 检查通过后，选择 **4 → 7**，按数字选组，再选 **WARP**。终端中运行 `any add` 时也会询问出口。
3. 客户端刷新原订阅，再实际测试目标网站。密码、订阅 URL 和 AnyTLS 端口保持不变。

自动安装支持 Debian 12/13；普通安装和更新不会启用 WARP。已有独立 WARP 配置只做检查，不自动接管。WARP 分组仅支持 **TCP**，故障时阻断该组流量，直连分组继续按原设置工作。

WARP 更换的是出口路径，**不保证 Grok 放行，也不提供住宅 IP 保证**。首次建议先用一个分组验证。[安装边界、DNS 与诊断](docs/operations.md#cloudflare-warp-出口)

## 更新

```bash
any self-update                   # 更新管理工具
any update                        # 更新 sing-box 核心
```

管理工具直接从 GitHub `main` 获取经过校验的源码，保留现有账号和证书。无需手工下载压缩包或指定版本号。更新、回退和备份方式见[维护说明](docs/operations.md#更新与备份)。

## 使用边界

- **分组共用凭据**：不能只撤销其中一人的访问。换密会更换该组密码和订阅链接，须重新分发；分组变更可能短暂中断现有连接。
- **证书需要维护**：证书续期后，分别重新导入代理和订阅证书；脚本不会自动同步宝塔文件。
- **连通性分开检查**：本机 TLS 成功不代表公网可达，连接失败先排查 DNS、端口和防火墙。
- **配置保存在服务器**：源码更新不上传密码、订阅令牌或证书私钥；运行数据和导出配置不应提交到 GitHub。
- **按可信成员分发**：当前未隔离服务器本机、私网和链路本地目的地址，也不提供按组限速、到期或设备数量限制。

[完整使用与维护](docs/operations.md) · [测试范围](src/TEST-RESULTS.txt) · [官方参考来源](src/SOURCES.txt)
