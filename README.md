# nft-forward-panel

一个基于 nftables 的端口转发管理脚本，支持交互式菜单和轻量 Web 面板。

## 功能

- 普通 TCP/UDP DNAT 端口转发管理
- DNS 动态转发管理
- Web 面板添加、删除、重载规则
- 规则列表内一键测试目标连通性
- Web 面板登录信息、端口、监听 IP 配置
- 支持为面板申请真实 IP 证书，不生成自签证书
- IP 证书默认安装路径：
  - 证书：`/etc/panel-ssl/nft-ip-cert.crt`
  - 私钥：`/etc/panel-ssl/nft-ip-private.key`
- 通过 acme.sh 自动续期 IP 证书，自动检查 cron/crond，续期后自动重启面板
- 自动生成 nftables 配置
- 可选防火墙端口放行
- 配置备份与诊断菜单

## 使用

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/chenzai666/nft-forward-panel/main/nft.sh?$(date +%s)" | tr -d '\r')
```

也可以手动下载后执行：

```bash
chmod +x nft.sh
sudo ./nft.sh
```

Web 面板入口在主菜单：

```text
9) Web 面板管理
```

默认面板端口是 `4788`，安装时可以自定义用户名、密码和端口。

## HTTPS / IP 证书

在 Web 面板管理中选择：

```text
5) 配置监听 IP / HTTPS 证书
```

证书和私钥路径直接回车会使用默认路径：

```text
/etc/panel-ssl/nft-ip-cert.crt
/etc/panel-ssl/nft-ip-private.key
```

如果文件不存在，脚本会尝试使用 Let's Encrypt 申请真实 IP 证书。申请 IP 证书要求：

- 使用公网 IPv4，不能使用 `0.0.0.0`、`127.0.0.1` 或内网 IP
- 公网 80 端口能访问到这台服务器
- 系统可以安装并运行 `acme.sh`
- 首次申请和定时续期时如果检测到 nginx 正在运行，脚本会临时停止 nginx 释放 80 端口；无论成功或失败，都会自动恢复 nginx。未运行 nginx 时不会启动它。
- 最近一次有效的证书公网 IP 会保存到 `/etc/nftables.d/panel-cert-ip`，下次申请时直接作为默认值。
- 更新脚本时，旧路径 `/root/ygkkkca/cert.crt` 与 `private.key` 会自动复制到新路径，并同步 acme.sh 的续期安装路径；旧文件会保留，确认服务正常后可自行删除。

如需关闭 HTTPS，证书和私钥路径都输入 `none`。

## 安全提醒

- 建议只在可信网络、VPN 或防火墙白名单内开放 Web 面板端口。
- 脚本默认不会清空全局 nftables 规则集。
- BBR + fq 网络优化需要手动确认启用。
- 执行前建议先备份现有规则：

```bash
nft list ruleset > /root/nft.rules.backup
iptables-save > /root/iptables.rules.backup
```
