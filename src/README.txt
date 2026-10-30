AnyHarbor 1.7.4 — 使用与维护

项目：https://github.com/JackieSung4ev/AnyHarbor
详细说明：https://github.com/JackieSung4ev/AnyHarbor/blob/main/docs/operations.md
支持 Debian 12/13、Ubuntu 22.04/24.04/26.04 + systemd、amd64/arm64；管理命令需要 root，代理进程使用专用系统用户。使用官方 sing-box 核心。
安装入口及前置条件见项目首页。需要域名、有效证书链及私钥文件路径，向导询问端口和节点前缀。
源码更新只下载代码，不上传密码、证书私钥或订阅令牌。

一、日常入口

输入 any 打开数字菜单，按数字选择操作和分组：
  1 状态与连接检查    2 导出全部节点格式    3 HTTPS 订阅
  4 分组管理          5 地址/端口/证书/前缀 6 更新与回退
  7 查看日志          8 重启服务           0 退出
  11 Cloudflare WARP 出口（可选，不随普通安装或升级启用）

any add 自动随机新增一个希腊英文名分组，生成独立密码和订阅令牌；终端中询问出口，默认直连。
默认10组，最多100组，包含停用组。最后一个启用组不能停用或删除。

二、节点和订阅

  any group list                 查看组ID
  any export athena              显示指定组全部格式，包含标题
  any export athena clash        只输出原始Clash YAML
  any export athena v2rayn       只输出v2rayN分享链接
  any export athena shadowrocket 只输出标准AnyTLS分享链接
  any sub athena                 显示指定组全部订阅链接

保存文件时先设置umask 077，并指定单一格式；默认组合输出含标题，不直接当配置导入。
Clash/Mihomo使用/s/订阅；v2rayN使用/v/；Shadowrocket使用/r/。
/v/为Base64编码的v2rayn://anytls/…，/r/为Base64编码的anytls://列表。
订阅已经编码，不要二次编码；Clash YAML转Base64不会变成Shadowrocket订阅。
客户端须支持AnyTLS，格式验证不等于所有客户端应用版本均已实测。
Shadowrocket/标准URI只用于可信证书模式，自签/固定证书模式不关闭验证来生成通用链接。

分组共用账号，不能只撤销组内一人。换密同时更换密码和订阅令牌，必须分发新配置或链接：
  any group rotate athena
停用/启用也会作废原凭据；其他组凭据保留。分组变更会重启代理，建议低峰操作。

三、HTTPS订阅

需要可信域名证书、正确DNS和可用Nginx。已有宝塔/Nginx时复用；未安装时 Debian 安装 nginx-light，Ubuntu 安装 nginx。
运行any → 3 → 1，或any subscription enable。默认复用已导入域名和证书，只询问端口。
默认订阅TCP端口9443，必须与代理端口不同，均在1024..65535范围内，并分别放行防火墙。
使用其他域名或新证书时选择3 → 8；分发链接使用3 → 3，只向成员提供所属组链接。

  any subscription status        查看服务与证书
  any subscription check athena  核对本地产物与本机HTTPS正文
  any subscription refresh       重新发布已启用订阅，复用保存的证书
  any subscription off           关闭下载，已导入代理账号仍有效

启用、调整、刷新或关闭订阅可能重启服务。撤销账号必须换密、停用或删除组，不能只关订阅。
完整订阅URL也是凭据，不能公开整个分发表。检查本机正文不会验证公网DNS/CDN或缓存。

Clash默认分流规则：
新安装自动带516条内置规则，无需上传文件。指定直连/代理/拦截规则优先，
随后GEOIP,CN,DIRECT，最后MATCH,PROXY；不是所有大陆网站都保证直连。
未导入自定义规则时，self-update会使用当前内置规则；已导入的自定义规则保留。
运行any rules，或any → 3 → 10。子菜单1状态、2导入、3显示、4恢复内置、0返回。
  any rules import /root/clash-rules.json  可选：导入本机自定义规则
  any rules show                         显示当前规则
  any rules reset                        清除自定义覆盖，恢复当前内置规则

文件是UTF-8 JSON字符串数组，不是完整YAML，也不是改后缀即可。大陆IP直连、其余代理的最小示例：
  ["GEOIP,CN,DIRECT", "MATCH,PROXY"]
从已有Clash配置只提取rules列表，保留每条字符串和顺序，不包含节点、代理组或DNS等设置。
支持DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6、GEOIP、MATCH；
IP/GEOIP可带no-resolve，1..5000条，最后必须是唯一的MATCH,PROXY；域名使用ASCII/Punycode。
Proxy统一为PROXY；PROXY组只含当前分组节点，不混入其他组账号。
不支持的规则或目标拒绝导入，原配置保留；多个节点或外部规则源不能直接照搬。
既有和新增分组的完整Clash导出及/s/订阅共用本机规则，客户端更新原订阅并使用规则模式。
只导入节点片段不含分流规则；v2rayN、Shadowrocket格式和服务端直连/WARP设置不受影响。
DIRECT由客户端直连，PROXY流量进入AnyTLS后才按分组选择服务端出口。
导入/重置不重启代理服务、不换密码或订阅URL，通常无需另跑subscription refresh。
内置规则随公开源码维护；自定义规则留在运行数据中，正常更新及核心回滚保留，不上传GitHub。
只有需要自定义覆盖时，才需在每台服务器分别导入；默认安装不需要这一步。
管理代码回退会拒绝不支持当前规则的旧版本；不要直接运行旧版脚本绕过兼容检查。
1.7.4起reset不再恢复为仅MATCH,PROXY；需要全代理可导入仅含这条规则的JSON数组。
客户端更新原订阅后才收到规则变化；地区分类与实际可用性仍需客户端验证。

四、证书与节点前缀

脚本保存证书副本，不申请、不续期、不自动同步宝塔原文件。证书续期后分别导入：
  代理：any → 5 → 3
  订阅：any → 3 → 8
快捷启用和subscription refresh使用旧副本，不会自动读取续期后的原文件。

Clash的client-fingerprint: chrome是客户端TLS握手特征，保持输出。
fingerprint是服务器完整证书SHA256，仅在pin模式输出。可信证书pki模式使用SNI和
skip-cert-verify:false验证信任链及域名，不需要再补证书指纹。固定证书变化后旧指纹失效。
v2rayN的Fingerprint: chrome也是客户端握手特征，pin模式另用Cert保存公开证书。

any prefix US-01修改本机节点前缀，客户端刷新订阅后显示US-01 AnyTLS · Athena等。
改前缀不换凭据；不同服务器须使用对应的地址、证书和端口，显示名不改变实际连接目标。

五、诊断、更新与备份

  any status               查看服务、证书和本机TLS检查
  any logs                 查看日志
  any check-update         检查管理工具更新
  any self-update          更新管理工具
  any update               更新官方sing-box核心
  any manager-rollback     回退管理代码
  any rollback             回滚核心、端口或证书

管理工具通过GitHub main获取并校验源码。回退管理代码保留当前账号并检查兼容性；
回滚核心/配置保留当前分组、撤销状态及自定义Clash规则，但地址、端口或证书可能恢复为旧值。
运行数据在/opt/jackie-anytls/，备份整个目录及服务单元/启动器，不只复制current软链接。
备份含密码、令牌、私钥和历史凭据，应妥善保管，不上传GitHub。卸载会停用服务但保留数据。

本机TLS成功不等于公网可达。公网TCP失败先查DNS、安全组、系统防火墙及网络路径；
TCP成功但代理失败，再核对客户端协议支持、密码、SNI、证书和服务日志。
Windows公网测试：Test-NetConnection proxy.example.com -Port 8443（替换域名和实际端口）。
NO_COLOR=1 any可关闭菜单颜色。

当前未隔离代理对服务器本机、私网和链路本地目的地址的访问，请按可信成员分发并加固网络边界。
不提供按组限速、到期、设备数量限制或自动流量统计；容量取决于并发、带宽和流量额度。
官方来源与实际测试范围分别见SOURCES.txt和TEST-RESULTS.txt。

六、可选 Cloudflare WARP 出口

运行 any → 11 → 1，阅读 Cloudflare 条款后，必须原样输入大写 WARP 才会安装官方软件包并设置本机代理。直接回车取消。
自动安装仅支持 Debian 12/13、Ubuntu 22.04/24.04/26.04、amd64/arm64；已有 WARP/MDM 不会被自动接管。
本机 SOCKS 固定127.0.0.1:40000，使用proxy/MASQUE，不启用整机隧道、不对公网开放此端口。
设置成功后，在4 → 7或11 → 3按数字选组，切换直连/WARP；同组全部成员共用出口。
  any warp check                     检查监听及经代理的HTTPS出口
  any group egress athena warp        切换整组至WARP
  any group egress athena direct      恢复该组直连
  any warp connect                   重连本工具管理的WARP，已有WARP连接短暂中断
  any warp logs                      查看官方客户端日志

出口切换保留密码、订阅URL、入站端口和证书；客户端刷新原订阅即可。
WARP分组仅TCP，UDP在服务端拒绝；WARP失效时阻断该组，不回落直连。
域名目标交给SOCKS解析，但客户端自行使用的DNS不因此自动进入WARP。
warp=on/plus检查不保证Grok放行，不保证住宅IP；长连接和目标网站应先单组实测。
启用WARP后数据升级为schema3，回退不支持WARP的旧管理器会被拒绝，正常self-update仍可用。
卸载AnyHarbor会保留Cloudflare客户端、注册和官方APT源，按官方流程另外维护。
