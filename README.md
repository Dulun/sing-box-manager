# sing-box-manager

sing-box 轻量管理脚本，只做两件事：

1. **VLESS + Reality**（TCP 443，伪装域名可改）
2. **Hysteria2 + Salamander 混淆**（UDP 443，自签证书 + 指纹）

另外自带两样东西：

3. **服务端拦截**：微信 / 支付宝 / 银行 / 政府域名在服务器直接拒绝，客户端开全局也不会走代理（规则在 `sb.sh` 顶部的 `REJECT_DOMAINS` 里改）。
4. **订阅服务**：生成 Clash / Shadowrocket / sing-box 订阅文件，nginx 按客户端 UA 分流。

## 安装

直接跑菜单：

```bash
sudo bash <(wget -qO- https://raw.githubusercontent.com/Dulun/sing-box-manager/main/sb.sh)
```

或者先下载再跑：

```bash
wget https://raw.githubusercontent.com/Dulun/sing-box-manager/main/sb.sh -O sb.sh
chmod +x sb.sh
sudo ./sb.sh
```

用 curl 也行：

```bash
curl -fsSL https://raw.githubusercontent.com/Dulun/sing-box-manager/main/sb.sh -o sb.sh
chmod +x sb.sh
sudo ./sb.sh
```

## 用法

```bash
sudo ./sb.sh                    # 打开菜单
sudo ./sb.sh add-vless [--port 443] [--sni www.microsoft.com] [--name TR-VLESS] [--ipv6|--ipv4|--ip <v4|v6|both|auto|IP>]
sudo ./sb.sh add-hy2   [--port 443] [--name TR-Hy2] [--up 200] [--down 1000] [--ipv6|--ipv4|--ip <v4|v6|both|auto|IP>]
sudo ./sb.sh list               # 显示所有节点：链接 + Clash 配置 + 订阅地址
sudo ./sb.sh clash              # 生成 Clash 配置
sudo ./sb.sh sub                # 生成订阅文件并启动订阅服务
sudo ./sb.sh reject             # 查看并重新应用服务端拦截规则（菜单第 10 项）
sudo ./sb.sh set-ip [v4|v6|both|auto|<具体IP>]  # 改节点 IP：换服务器 IP 或想 v4/v6 都要时用（菜单第 11 项）
sudo ./sb.sh set-sub-port <端口>  # 改订阅端口，例如 443（菜单第 12 项；端口被 VLESS 之类的占了会拒绝）
sudo ./sb.sh status | restart | logs | uninstall
```

`--ip both` / `set-ip both`：v4 和 v6 各建一个节点（v6 的名字加 `-v6` 后缀），Clash 里两个都能选。

订阅地址（`sub` 会打印出来）：

```
http://<服务器IP>:62201/<TOKEN>/auto
```

## 文件说明

| 文件 | 说明 |
| ---- | ---- |
| `sb.sh` | 管理脚本本体 |
| `reject-cn-domains.json` | 服务端拦截的域名列表（微信 / 支付宝 / 银行 / gov.cn） |
| `deploy_reject.py` | 把拦截规则写进已有的 fscarmen 分文件配置（`/etc/sing-box/conf/03_route.json`） |

## 注意

- 改配置前自动备份，改完先跑 `sing-box check` 校验通过才重载。
- Hy2 证书校验：链接用 `pinSHA256` 固定证书，Clash 配置用 `fingerprint`，sing-box 客户端配置用 `certificate_public_key_sha256`；不跳过证书校验。
- `clash-local.yaml` 是个人 Clash 配置（含节点密码），不要放进仓库。

## 15. 免责声明

本程序仅供学习了解，非盈利目的，请于下载后 24 小时内删除，不得用作任何商业用途，文字、数据及图片均有所属版权，如转载须注明来源。

使用本程序必须遵守部署服务器所在地、所在国家和用户所在国家的法律法规，程序作者不对使用者任何不当行为负责。
