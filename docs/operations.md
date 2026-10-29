# 使用与维护

[返回首页](../README.md)

## 导出与导入

运行 `any` → **2**，按数字选组，复制适合客户端的区段。Clash / Mihomo 使用 YAML，v2rayN 使用 `v2rayn://anytls/…`，Shadowrocket 使用 `anytls://…`。

v2rayN 可在主界面按 `Ctrl+V` 导入完整单行链接，并使用支持 AnyTLS 的 sing-box 核心。Shadowrocket 可从剪贴板导入通用 AnyTLS 链接，订阅选择标明 Shadowrocket 的 `/r/…` URL。各客户端须使用支持 AnyTLS 的版本；软件名称相近不代表格式兼容，尤其不要把 v2rayNG 与 v2rayN 等同。

本工具按[官方 AnyTLS URI 规范](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)生成通用链接，只用于正常 CA 验证的证书。固定证书模式仍可导出 Clash 与 v2rayN；不会为了生成通用链接而关闭证书校验。协议与订阅测试范围见[测试说明](../src/TEST-RESULTS.txt)，不代表所有手机应用版本均已实测。

| 目的 | 命令 |
| --- | --- |
| 查看分组 ID | `any group list` |
| 显示一个分组的全部格式 | `any export athena` |
| 只显示原始 Clash YAML | `any export athena clash` |
| 只显示原始 v2rayN 链接 | `any export athena v2rayn` |
| 只显示原始 Shadowrocket 链接 | `any export athena shadowrocket` |

保存纯配置时指定单一格式：

```bash
umask 077
any export athena clash > /root/athena.yaml
any export athena v2rayn > /root/athena-v2rayn.txt
any export athena shadowrocket > /root/athena-shadowrocket.txt
```

默认 `export` 含阅读标题，不能整段当作配置导入。命令失败后不要导入产生的空文件。静态节点在地址、端口或密码变化后需要重新分发；订阅可更新常规配置，换密时仍须分发新 URL。

## 分组管理

运行 `any` → **4** 按数字操作，或使用以下命令：

| 操作 | 命令 | 影响 |
| --- | --- | --- |
| 自动新增 | `any add` | 随机英文名、独立密码和订阅令牌 |
| 修改显示名 | `any group rename athena Support` | 保留 ID 和凭据 |
| 换密 | `any group rotate athena` | 更换密码及订阅令牌 |
| 停用 | `any group disable athena` | 停用并作废原凭据 |
| 启用 | `any group enable athena` | 生成新凭据，原凭据不恢复 |
| 删除 | `any group remove athena` | 删除分组，原凭据失效 |

默认创建 10 组，最多 100 组，包含停用组。自动命名会避开已有名称，基础名字用完后添加数字后缀。最后一个启用组不能停用或删除。

组内成员共用凭据，不能只撤销其中一个人。换密后必须重新分发新节点或订阅链接，刷新旧链接不会得到新密码。分组变更会重启代理服务，建议在低峰操作；其他组的凭据保留。

多台服务器使用不同节点前缀，菜单 **5 → 5** 或：

```bash
any prefix US-01
```

节点显示为 `US-01 AnyTLS · Athena` 等。改前缀不换密码或订阅 URL；客户端刷新订阅即可看到新名称。前缀仅影响显示，域名、证书和端口仍须对应实际服务器。

## 在线订阅

订阅需要已解析到本机的域名、有效的完整证书链及私钥，以及可用的 Nginx。已有宝塔或其他 Nginx 时复用现有程序并确保 `nginx` 在 PATH 中；尚未安装时：

```bash
apt-get update && apt-get install -y nginx-light
```

运行 `any` → **3 → 1**，或：

```bash
any subscription enable
```

首次启用默认复用代理的 TLS 域名与已导入证书副本；配置过订阅时复用订阅设置。通常只询问端口，默认 `9443`。自签证书不符合 HTTPS 订阅要求；需要其他域名或证书时，使用菜单 **3 → 8**。

完整参数命令如下，替换示例域名、文件路径和端口：

```bash
any subscription enable proxy.example.com \
  /www/server/panel/vhost/cert/proxy.example.com/fullchain.pem \
  /www/server/panel/vhost/cert/proxy.example.com/privkey.pem \
  9443
```

代理端口与订阅端口必须不同，范围均为 `1024..65535`，需要分别在云和主机防火墙中放行 TCP。订阅使用独立 Nginx 配置，不修改现有网站；启用或调整订阅会重启订阅和代理服务。

运行 `any` → **3 → 3** 按数字选组，或：

```bash
any sub athena
```

| 路径 | 正文 | 使用方 |
| --- | --- | --- |
| `/s/…` | 完整 Clash YAML | Clash / Mihomo |
| `/v/…` | Base64 编码的 `v2rayn://anytls/…` | v2rayN |
| `/r/…` | Base64 编码的 `anytls://…` | Shadowrocket / 支持此格式的客户端 |

三种格式共用该分组账号和令牌，URL 路径决定内容。只分发对应分组的完整 URL，不复制标题或 CSV 整行。URL 本身就是访问凭据，不能公开整个分发表。令牌相同可能让下载工具给出相同文件名，应根据正文判断格式。

检查发布内容：

```bash
any subscription check athena
```

这会核对本地产物，并经验证 TLS 的本机 HTTPS 请求检查实际正文，不输出密码、令牌或配置。它不验证客户端公网 DNS、CDN、代理或缓存；端口可达、根路径返回 404 也不等于订阅正文正确。

`any subscription refresh` 重新发布已启用订阅，复用保存的证书副本并短暂重启服务。`any subscription off` 停止下载订阅，**已导入的代理账号仍然有效**；撤销访问须对分组换密、停用或删除。

## 汇总多个服务器

在每台服务器导出同一分组的通用链接，例如 `any export apollo shadowrocket`。把 `anytls://…` 按每行一条保存为 UTF-8 纯文本 `nodes.txt`，统一编码一次：

```bash
umask 077
base64 -w 0 nodes.txt > subscription.txt && printf '\n' >> subscription.txt
```

将结果作为纯文本放到自行管理的 HTTPS URL，再向 Shadowrocket 添加该 URL。不要混入标题或 YAML，也不要直接拼接多份已编码的订阅。

每个分组维护自己的汇总列表。手工汇总是快照，原节点换密、改地址或端口后要重新导出更新；它不会自动追踪各服务器。Base64 不是加密，含凭据的文件不能提交到项目仓库。

## 证书维护

### 两种指纹

Clash 的 `client-fingerprint: chrome` 控制客户端 TLS 握手特征，当前导出保留；`fingerprint` 是服务器完整证书的 SHA-256，用于固定证书。

可信证书默认使用 `pki` 模式：保留 SNI 和 `skip-cert-verify: false`，客户端验证证书信任链及域名，无需补 `fingerprint`。自签或显式 `pin` 模式才输出证书指纹。Mihomo 对叶子证书指纹采用匹配验证，并非简单叠加常规校验；固定的证书改变后旧指纹会失效。[官方说明](https://wiki.metacubex.one/config/proxies/tls/#fingerprint)

v2rayN 的 `Fingerprint: chrome` 同样对应客户端握手特征；固定证书模式另用 `Cert` 保存公开证书。标准 AnyTLS URI 没有通用指纹参数，因此通用链接只用于可信证书模式，保留 `sni` 与 `insecure=0`。

### 证书续期

脚本保存证书副本，不申请证书、不自动续期，也不监控宝塔原文件。源文件续期后，在菜单 **5 → 3** 重新导入代理证书：

```bash
any import-cert \
  /www/server/panel/vhost/cert/proxy.example.com/fullchain.pem \
  /www/server/panel/vhost/cert/proxy.example.com/privkey.pem \
  proxy.example.com
```

启用订阅时还需通过 **3 → 8** 导入订阅的新证书，或带完整参数执行 `subscription enable`。无参数快捷启用和 `subscription refresh` 都复用保存的副本，不会自动读取续期文件。

同域名可信证书正常续期不需要换组密码或重新固定指纹；固定证书模式换证后须更新客户端。`import-cert` 修改证书和 SNI，不修改客户端连接地址；改地址使用 `any server proxy.example.com`。这些操作可能重启代理服务。

## 连接诊断

```bash
any status
any logs
```

客户端 Windows PowerShell 测试实际域名和端口：

```powershell
Test-NetConnection proxy.example.com -Port 8443
```

| 现象 | 检查方向 |
| --- | --- |
| 本机 TLS 成功，公网 TCP 失败 | DNS、云安全组、主机防火墙及网络路径 |
| TCP 成功，代理访问失败 | 客户端 AnyTLS 支持、密码、SNI、证书有效期与服务日志 |
| 订阅打不开 | `any subscription status`，核对域名、端口和证书 |
| 订阅正文错误 | `any subscription check 组ID`，区分本地发布与外部缓存问题 |
| 订阅能下载但不能导入 | 客户端版本与所选格式，不要重复编码或混入标题 |
| 订阅服务启动失败 | `journalctl -u jackie-anytls-sub.service -n 60 --no-pager` |
| 换密后原链接失效 | 重新分发新链接，这是撤销原凭据的预期行为 |

服务运行或本机检查成功不代表公网可用。`NO_COLOR=1 any` 可关闭菜单颜色。

## 更新与备份

| 操作 | 命令 |
| --- | --- |
| 检查管理工具更新 | `any check-update` |
| 更新管理工具 | `any self-update` |
| 更新官方 sing-box 核心 | `any update` |
| 回退管理代码 | `any manager-rollback` |
| 回滚核心、端口或证书 | `any rollback` |

管理工具跟随 GitHub `main`，只读取白名单源码并校验后升级。管理代码回退保留当前账号与运行数据并检查兼容性；核心或配置回滚保留当前分组和撤销状态，但可能恢复旧地址、端口或证书，需要同步客户端。

运行数据位于 `/opt/jackie-anytls/`。备份整个目录，不能只备份 `current` 软链接；同时保存相关服务单元及启动器。备份包含密码、令牌、私钥和历史凭据，应按敏感数据保管，不能上传到公开仓库。

卸载会停用服务、删除管理命令，保留运行数据。不要删除数据目录来绕过安装检查；恢复或跨服务器迁移前先核对证书、DNS、权限与端口。

## 权限边界

当前代理未隔离服务器本机、私网和链路本地目的地址，持有效账号的成员可能访问服务器可达的内部服务。仅向可信成员分发，按实际环境另行设置网络边界。

本工具不提供按组限速、到期、设备数量限制或自动流量统计。可承载人数取决于并发、带宽和流量额度，不能只按内存容量判断。
