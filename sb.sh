#!/bin/bash
# ============================================================================
# sing-box 轻量管理脚本 (mini 版)
#
# 只做两件事，都是你现在用的：
#   1. VLESS + Reality (TCP 443, 伪装 www.microsoft.com)
#   2. Hysteria2 + Salamander 混淆 (UDP 443, 自签证书 + 指纹)
#
# 另外自带两样东西，都是跟你现在服务器上一样的：
#   3. 服务端拦截：微信 / 支付宝 / 银行 / 政府域名在服务器直接拒绝，
#      客户端开全局也不会走代理（规则在 REJECT_DOMAINS 里改）。
#   4. 订阅服务：生成 Clash / Shadowrocket / sing-box 订阅文件，
#      nginx 按 UA 分流，订阅地址见 ./sb.sh sub。
#
# 和 fscarmen 全家桶的区别：它支持十几种协议、Argo、WARP……
# 这个只做上面这些，代码就这一个文件，每一行都能看懂。
#
# 用法：
#   sudo ./sb.sh                    # 打开菜单
#   sudo ./sb.sh add-vless [--port 443] [--sni www.microsoft.com] [--name TR-VLESS] [--ipv6|--ipv4|--ip <v4|v6|auto|IP>]
#   sudo ./sb.sh add-hy2   [--port 443] [--name TR-Hy2] [--up 200] [--down 1000] [--ipv6|--ipv4|--ip <v4|v6|auto|IP>]
#   sudo ./sb.sh list               # 显示所有节点：链接 + Clash 配置
#   sudo ./sb.sh clash              # 生成 Clash 配置（规则跟你现在用的一套）
#   sudo ./sb.sh sub                # 生成订阅文件并启动订阅服务
#   sudo ./sb.sh reject             # 查看并重新应用服务端拦截规则（菜单里第 10 项）
#   sudo ./sb.sh set-ip [v4|v6|auto|<具体IP>]  # 改节点 IP：换服务器 IP 或想固定用 v6 时用
#   sudo ./sb.sh status | restart | logs | uninstall
#
# 白名单直连域名（空格分隔）：这些走直连，其余全部走代理。
# 改这里，然后重新跑 ./sb.sh clash 重新生成配置。
WHITELIST_DOMAINS="ezhiben.com apsaradb.com aliyuncs.com bilibili.com hdslb.com bilivideo.com biliapi.net biliapi.com"
#
# 服务端拦截域名（空格分隔）：这些域名在服务器端直接拒绝，
# 哪怕客户端开全局模式也不会走代理。改这里，然后跑 ./sb.sh reject
# 或任意一次 add / restart 都会重新应用。
REJECT_DOMAINS="weixin.qq.com wx.qq.com wechat.com qq.com tenpay.com alipay.com alipay.cn alipayobjects.com alipayplus.com alipayhk.com antfin.com gov.cn icbc.com icbc.com.cn ccb.com ccbank.com.cn abchina.com abchina.com.cn boc.cn bankofchina.com bankcomm.com bankcomm.cn cmbchina.com psbc.com ecitic.com citicbank.com cebbank.com spdb.com.cn cib.com.cn cmbc.com.cn pingan.com hxb.com.cn cgbchina.com.cn czbank.com cbhb.com.cn hengfengbank.com bankofbeijing.com.cn bankofshanghai.com bosh.cn jsbchina.cn nbcb.com.cn nbcb.cn njcb.com.cn unionpay.com unionpaysecure.com"
#
# 订阅服务端口（nginx 监听，TCP）
SUBSCRIBE_PORT="62201"
#
# 文件位置：
#   配置：/etc/sing-box/config.json（改之前自动备份成 config.json.bak）
#   节点记录：/etc/sb-manager/nodes.json（只存你自己的节点信息）
#   生成的 Clash 配置：/etc/sb-manager/clash.yaml
#   IP 偏好：/etc/sb-manager/ip_mode（auto / v4 / v6 / 具体 IP，用 ./sb.sh set-ip 改）
#
# 注意：每次改配置后都会先跑 sing-box check，校验通过才重载服务。
# ============================================================================
set -euo pipefail

SB_BASE="${SB_TEST_DIR:-/etc/sing-box}"
SB_STATE_DIR="${SB_TEST_DIR:-/etc/sb-manager}"
CONFIG="$SB_BASE/config.json"
NODES="$SB_STATE_DIR/nodes.json"
CERT="$SB_BASE/cert.pem"
KEY="$SB_BASE/key.pem"
SUBSCRIBE_DIR="$SB_STATE_DIR/subscribe"
SUBSCRIBE_TOKEN_FILE="$SB_STATE_DIR/subscribe_token"
SUBSCRIBE_NGINX_CONF="$SB_STATE_DIR/nginx.conf"

# ---------- 基础工具 ----------

need_root() {
  if [ -n "${SB_TEST_DIR:-}" ]; then return 0; fi  # 测试模式跳过
  if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root 运行：sudo $0 $*" >&2
    exit 1
  fi
}

# 服务器公网 IP：偏好存在 $SB_STATE_DIR/ip_mode 里（auto / v4 / v6 / 具体 IP）
# 默认 auto：优先 v4，没有再用 v6。改偏好用 ./sb.sh set-ip。
server_ip() {
  local mode ip
  mode=$(cat "$SB_STATE_DIR/ip_mode" 2>/dev/null || echo auto)
  case "$mode" in
    v6)
      ip=$(curl -s6 --max-time 5 https://ifconfig.me || true) ;;
    v4)
      ip=$(curl -s4 --max-time 5 https://ifconfig.me || true) ;;
    auto|"")
      ip=$(curl -s4 --max-time 5 https://ifconfig.me || true)
      if [ -z "$ip" ]; then
        ip=$(curl -s6 --max-time 5 https://ifconfig.me || true)
      fi ;;
    *)  # 写死了一个具体 IP，直接用
      ip="$mode" ;;
  esac
  echo "$ip"
}

# 改节点 IP：set-ip [v4|v6|auto|<具体IP>]
#   v4 / v6 / auto：改自动探测的偏好；具体 IP：写死这个地址。
#   改完把已建节点的 server 全换掉，并重新生成 Clash 配置和订阅。
set_ip() {
  local arg="${1:-}"
  if [ -z "$arg" ]; then
    echo "当前 IP 偏好：$(cat "$SB_STATE_DIR/ip_mode" 2>/dev/null || echo auto)"
    echo "当前服务器 IP：$(server_ip)"
    echo "用法：$0 set-ip [v4|v6|auto|<具体IP>]"
    echo "  v4 / v6：之后建节点只用对应协议的 IP"
    echo "  auto：优先 v4，没有再用 v6（默认）"
    echo "  具体 IP：写死这个 IP（换了服务器 IP 或想固定用某个地址时用）"
    return 0
  fi
  need_root
  init_config
  case "$arg" in
    v4|v6|auto) echo "$arg" > "$SB_STATE_DIR/ip_mode" ;;
    *:*|*.*.*.*) echo "$arg" > "$SB_STATE_DIR/ip_mode" ;;
    *) echo "不认识：$arg（用 v4 / v6 / auto / 具体 IP）" >&2; exit 1 ;;
  esac
  local ip count
  ip=$(server_ip)
  if [ -z "$ip" ]; then echo "拿不到服务器公网 IP，请检查网络" >&2; exit 1; fi
  # 更新已建节点的 server
  IP="$ip" python3 - "$NODES" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    nodes = json.load(f)
for n in nodes:
    n["server"] = os.environ["IP"]
with open(path, "w") as f:
    json.dump(nodes, f, indent=2)
PYEOF
  count=$(python3 -c "import json; print(len(json.load(open('$NODES'))))")
  if [ "$count" -gt 0 ]; then
    echo "节点 IP 已改为：$ip（$count 个节点已更新），正在重新生成 Clash 配置和订阅……"
    gen_clash >/dev/null
    gen_subscribe
  else
    echo "IP 偏好已保存（当前 $ip）。还没有节点，之后建节点会用这个 IP。"
  fi
}

# URL 编码节点名（生成链接用）
urlencode() {
  python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" "$1"
}

# 拼 host:port：IPv6 要加方括号，否则链接里分不清地址和端口
fmt_hostport() {
  local ip="$1" port="$2"
  case "$ip" in
    *:* ) echo "[$ip]:$port" ;;
    * )   echo "$ip:$port" ;;
  esac
}

# ---------- 安装与配置 ----------

ensure_singbox() {
  if command -v sing-box >/dev/null 2>&1; then
    echo "sing-box 已安装：$(sing-box version | head -n 1)"
    return 0
  fi
  echo "正在安装 sing-box（官方脚本）……"
  bash <(curl -fsSL https://sing-box.app/install.sh)
}

init_config() {
  mkdir -p "$SB_BASE" "$SB_STATE_DIR"
  if [ ! -f "$CONFIG" ]; then
    cat > "$CONFIG" <<'EOF'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
  fi
  if [ ! -f "$NODES" ]; then
    echo '[]' > "$NODES"
  fi
  ensure_reject_route
}

# ---------- 服务端拦截：微信 / 支付宝 / 银行 / 政府域名直接拒绝 ----------
# 幂等：重复跑只会刷新同一条规则，不会重复添加。
# 位置：sniff 规则之后，其它路由规则之前；没匹配上的流量照常走 direct。
ensure_reject_route() {
  REJECT_DOMAINS="$REJECT_DOMAINS" python3 - "$CONFIG" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
domains = os.environ.get("REJECT_DOMAINS", "").split()
with open(path) as f:
    cfg = json.load(f)
route = cfg.setdefault("route", {})
rules = route.get("rules", [])
# 删掉旧的拦截规则（以微信域名为标记）
rules = [r for r in rules
         if not (r.get("action") == "reject"
                 and "weixin.qq.com" in r.get("domain_suffix", []))]
# 确保 sniff 在最前面（没有就补一个；sniff 是为了拿到 TLS 的 SNI，
# 客户端只发 IP 不发域名时也能靠 SNI 匹配上）
if not rules or rules[0].get("action") != "sniff":
    rules.insert(0, {"action": "sniff"})
rules.insert(1, {"action": "reject", "domain_suffix": domains})
route["rules"] = rules
cfg["route"] = route
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYEOF
}

# 查看服务端拦截规则
show_reject() {
  echo "服务端拦截规则（命中就拒绝，客户端开全局也不会走代理）："
  echo "$REJECT_DOMAINS" | tr ' ' '\n' | sed 's/^/  - /'
  echo ""
  echo "共 $(echo "$REJECT_DOMAINS" | wc -w) 个域名。想增减：改 sb.sh 顶部的 REJECT_DOMAINS，"
  echo "然后跑 ./sb.sh reject 应用（菜单里第 10 项也可以）。"
}

# 改配置前备份，校验通过才重载；失败则还原
reload_config() {
  cp "$CONFIG" "$CONFIG.bak"
  if ! sing-box check -c "$CONFIG"; then
    echo "配置校验失败，已还原备份" >&2
    cp "$CONFIG.bak" "$CONFIG"
    exit 1
  fi
  if [ -n "${SB_TEST_DIR:-}" ]; then
    echo "[测试模式] 跳过 systemctl"
    return 0
  fi
  if systemctl is-active --quiet sing-box 2>/dev/null; then
    systemctl restart sing-box
  else
    systemctl enable --now sing-box
  fi
  echo "sing-box 已重载"
}

# 防火墙放行（只有 ufw 在运行时才操作）
allow_port() {
  local port="$1" proto="$2"  # proto: tcp / udp
  if [ -n "${SB_TEST_DIR:-}" ]; then return 0; fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$port/$proto" >/dev/null
    echo "ufw 已放行 $port/$proto"
  fi
}

# ---------- 添加 VLESS + Reality ----------

add_vless() {
  local port=443 sni="www.microsoft.com" name="VLESS-Reality" ip_arg=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --port) port="$2"; shift 2 ;;
      --sni)  sni="$2";  shift 2 ;;
      --name) name="$2"; shift 2 ;;
      --ipv6) ip_arg="v6"; shift ;;
      --ipv4) ip_arg="v4"; shift ;;
      --ip)   ip_arg="$2"; shift 2 ;;
      *) echo "未知参数：$1" >&2; exit 1 ;;
    esac
  done

  need_root
  ensure_singbox
  init_config
  if [ -n "$ip_arg" ]; then
    echo "$ip_arg" > "$SB_STATE_DIR/ip_mode"
  fi

  local uuid keypair privkey pubkey shortid ip
  uuid=$(sing-box generate uuid)
  keypair=$(sing-box generate reality-keypair)
  privkey=$(echo "$keypair" | awk '/PrivateKey/{print $2}')
  pubkey=$(echo "$keypair" | awk '/PublicKey/{print $2}')
  shortid=$(openssl rand -hex 4)
  ip=$(server_ip)
  if [ -z "$ip" ]; then echo "拿不到服务器公网 IP，请检查网络" >&2; exit 1; fi

  # 写入 inbound（同名 tag 先删再加，重复添加 = 覆盖旧节点）
  PORT="$port" UUID="$uuid" PRIVKEY="$privkey" SHORTID="$shortid" SNI="$sni" \
    python3 - "$CONFIG" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
tag = "vless-%s" % os.environ["PORT"]
cfg["inbounds"] = [i for i in cfg.get("inbounds", []) if i.get("tag") != tag]
cfg["inbounds"].append({
    "type": "vless",
    "tag": tag,
    "listen": "::",
    "listen_port": int(os.environ["PORT"]),
    "users": [{"uuid": os.environ["UUID"], "flow": "xtls-rprx-vision"}],
    "tls": {
        "enabled": True,
        "server_name": os.environ["SNI"],
        "reality": {
            "enabled": True,
            "handshake": {"server": os.environ["SNI"], "server_port": 443},
            "private_key": os.environ["PRIVKEY"],
            "short_id": [os.environ["SHORTID"]]
        }
    }
})
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF

  # 记录节点信息（供 list 显示链接和 Clash 配置）
  NAME="$name" TYPE="vless" SERVER="$ip" PORT="$port" UUID="$uuid" \
  SNI="$sni" PUBKEY="$pubkey" SHORTID="$shortid" \
    python3 - "$NODES" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    nodes = json.load(f)
nodes = [n for n in nodes if not (n.get("type") == "vless" and str(n.get("port")) == os.environ["PORT"])]
nodes.append({
    "name": os.environ["NAME"], "type": "vless",
    "server": os.environ["SERVER"], "port": int(os.environ["PORT"]),
    "uuid": os.environ["UUID"], "sni": os.environ["SNI"],
    "public_key": os.environ["PUBKEY"], "short_id": os.environ["SHORTID"]
})
with open(path, "w") as f:
    json.dump(nodes, f, indent=2)
PYEOF

  allow_port "$port" tcp
  reload_config
  gen_subscribe
  echo ""
  echo "VLESS + Reality 节点已建好：$name ($(fmt_hostport "$ip" "$port"))"
  echo "用 ./sb.sh list 查看链接和 Clash 配置"
}

# ---------- 添加 Hysteria2 + Salamander ----------

add_hy2() {
  local port=443 name="Hy2" up=200 down=1000 ip_arg=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --port) port="$2"; shift 2 ;;
      --name) name="$2"; shift 2 ;;
      --up)   up="$2";   shift 2 ;;
      --down) down="$2"; shift 2 ;;
      --ipv6) ip_arg="v6"; shift ;;
      --ipv4) ip_arg="v4"; shift ;;
      --ip)   ip_arg="$2"; shift 2 ;;
      *) echo "未知参数：$1" >&2; exit 1 ;;
    esac
  done

  need_root
  ensure_singbox
  init_config
  if [ -n "$ip_arg" ]; then
    echo "$ip_arg" > "$SB_STATE_DIR/ip_mode"
  fi

  local password obfs_password ip fingerprint sni="addons.mozilla.org"
  password=$(sing-box generate uuid)
  obfs_password=$(openssl rand -hex 16)
  ip=$(server_ip)
  if [ -z "$ip" ]; then echo "拿不到服务器公网 IP，请检查网络" >&2; exit 1; fi

  # 自签证书（Hy2 必须有 TLS 证书；没有就用这个自签的，客户端用指纹校验）
  if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
      -days 3650 -nodes -subj "/CN=$sni" 2>/dev/null
    chmod 600 "$KEY"
  fi
  fingerprint=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2)

  PORT="$port" PASSWORD="$password" OBFS_PASSWORD="$obfs_password" SNI="$sni" \
  CERT="$CERT" KEY="$KEY" \
    python3 - "$CONFIG" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    cfg = json.load(f)
tag = "hy2-%s" % os.environ["PORT"]
cfg["inbounds"] = [i for i in cfg.get("inbounds", []) if i.get("tag") != tag]
cfg["inbounds"].append({
    "type": "hysteria2",
    "tag": tag,
    "listen": "::",
    "listen_port": int(os.environ["PORT"]),
    "users": [{"password": os.environ["PASSWORD"]}],
    "obfs": {"type": "salamander", "password": os.environ["OBFS_PASSWORD"]},
    "tls": {
        "enabled": True,
        "server_name": os.environ["SNI"],
        "certificate_path": os.environ["CERT"],
        "key_path": os.environ["KEY"]
    }
})
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF

  NAME="$name" TYPE="hy2" SERVER="$ip" PORT="$port" PASSWORD="$password" \
  OBFS_PASSWORD="$obfs_password" SNI="$sni" FINGERPRINT="$fingerprint" \
  UP="$up" DOWN="$down" \
    python3 - "$NODES" <<'PYEOF'
import json, os, sys
path = sys.argv[1]
with open(path) as f:
    nodes = json.load(f)
nodes = [n for n in nodes if not (n.get("type") == "hy2" and str(n.get("port")) == os.environ["PORT"])]
nodes.append({
    "name": os.environ["NAME"], "type": "hy2",
    "server": os.environ["SERVER"], "port": int(os.environ["PORT"]),
    "password": os.environ["PASSWORD"],
    "obfs_password": os.environ["OBFS_PASSWORD"],
    "sni": os.environ["SNI"],
    "fingerprint": os.environ["FINGERPRINT"],
    "up": os.environ["UP"], "down": os.environ["DOWN"]
})
with open(path, "w") as f:
    json.dump(nodes, f, indent=2)
PYEOF

  allow_port "$port" udp
  reload_config
  gen_subscribe
  echo ""
  echo "Hysteria2 节点已建好：$name ($(fmt_hostport "$ip" "$port"))，Salamander 混淆已开"
  echo "用 ./sb.sh list 查看链接和 Clash 配置"
}

# ---------- 查看节点 ----------

list_nodes() {
  init_config
  python3 - "$NODES" <<'PYEOF'
import json, sys, urllib.parse
with open(sys.argv[1]) as f:
    nodes = json.load(f)
if not nodes:
    print("还没有节点。先用 add-vless 或 add-hy2 添加一个。")
    sys.exit(0)
for n in nodes:
    name = n["name"]
    enc = urllib.parse.quote(name)
    # 链接里的 host：IPv6 必须加方括号；Clash 的 server 字段用裸 IP
    host = "[%s]" % n["server"] if ":" in n["server"] else n["server"]
    print("=" * 60)
    print("节点：%s  (%s:%s)" % (name, host, n["port"]))
    print("-" * 60)
    if n["type"] == "vless":
        link = ("vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision"
                "&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s"
                % (n["uuid"], host, n["port"], n["sni"],
                   n["public_key"], n["short_id"], enc))
        print("链接：")
        print(link)
        print("")
        print("Clash 配置：")
        print("- name: %s" % name)
        print("  type: vless")
        print("  server: %s" % n["server"])
        print("  port: %s" % n["port"])
        print("  uuid: %s" % n["uuid"])
        print("  tls: true")
        print("  servername: %s" % n["sni"])
        print("  reality-opts:")
        print("    public-key: %s" % n["public_key"])
        print("    short-id: %s" % n["short_id"])
        print("  client-fingerprint: chrome")
        print("  flow: xtls-rprx-vision")
        print("  udp: true")
    else:
        link = ("hysteria2://%s@%s:%s?obfs=salamander&obfs-password=%s"
                "&sni=%s&insecure=1#%s"
                % (n["password"], host, n["port"],
                   n["obfs_password"], n["sni"], enc))
        print("链接（insecure=1 为跳过证书校验；想更严格可用下面的指纹）：")
        print(link)
        print("")
        print("Clash 配置：")
        print("- name: %s" % name)
        print("  type: hysteria2")
        print("  server: %s" % n["server"])
        print("  port: %s" % n["port"])
        print("  password: %s" % n["password"])
        print("  obfs: salamander")
        print("  obfs-password: %s" % n["obfs_password"])
        print("  sni: %s" % n["sni"])
        print("  skip-cert-verify: false")
        print("  fingerprint: %s" % n["fingerprint"])
        print("  up: %s Mbps" % n["up"])
        print("  down: %s Mbps" % n["down"])
    print("")
PYEOF
}

# ---------- 生成 Clash 配置（白名单直连，其余全部代理） ----------

gen_clash() {
  init_config
  local out="$SB_STATE_DIR/clash.yaml"
  WHITELIST_DOMAINS="$WHITELIST_DOMAINS" python3 - "$NODES" "$out" <<'PYEOF'
import json, os, sys

nodes_path, out_path = sys.argv[1], sys.argv[2]
with open(nodes_path) as f:
    nodes = json.load(f)
if not nodes:
    print("还没有节点。先用 add-vless 或 add-hy2 添加一个。")
    sys.exit(1)

whitelist = os.environ.get("WHITELIST_DOMAINS", "").split()
names = [n["name"] for n in nodes]

out = []
out.append("# 由 sb.sh 生成：规则跟你现在用的 Clash 配置一致")
out.append("# 白名单域名在 sb.sh 顶部的 WHITELIST_DOMAINS 里改，改完重新跑 ./sb.sh clash")
out.append("# 微信 / 支付宝 / 银行 / 政府走直连；服务端还有一条拦截规则，开全局也不会走代理")
out.append("tun:")
out.append("  enable: true")
out.append("  stack: system")
out.append("  auto-route: true")
out.append("  auto-detect-interface: true")
out.append("  inet6-address: [fdfe:dcba:9876::1/64]")
out.append("  dns-hijack: [any:53]")
out.append("  mtu: 1500")
out.append("  route-exclude-address:")
out.append("    - 100.64.0.0/10")
out.append("    - fd7a:115c:a1e0::/48")
out.append("")
out.append("mixed-port: 7890")
out.append("allow-lan: true")
out.append("bind-address: '*'")
out.append("mode: rule")
out.append("log-level: info")
out.append("ipv6: false")
out.append("external-controller: 127.0.0.1:10000")
out.append("experimental:")
out.append("  ignore-resolve-fail: true")
out.append("sniffer:")
out.append("  enable: true")
out.append("  override-destination: true")
out.append("  force-dns-mapping: true")
out.append("  parse-pure-ip: true")
out.append("  sniff:")
out.append("    HTTP:")
out.append("      ports:")
out.append("      - 80")
out.append("      - 8080-8880")
out.append("      override-destination: true")
out.append("    TLS:")
out.append("      ports:")
out.append("      - 443")
out.append("      - 8443")
out.append("      override-destination: true")
out.append("    QUIC:")
out.append("      ports:")
out.append("      - 443")
out.append("      - 8443")
out.append("      override-destination: true")
out.append("dns:")
out.append("  enable: true")
out.append("  ipv6: true")
out.append("  listen: 0.0.0.0:1053")
out.append("  # redir-host：返回真实 IP，不用 198.18.x.x 的假地址")
out.append("  # （不用 fake-ip，就不会有应用拿到假地址导致的行为异常）")
out.append("  enhanced-mode: redir-host")
out.append("  # 国外域名走代理里的 DoH，本地 ISP 看不到你查了什么域名 = 不泄露")
out.append("  # 国内域名走国内 DNS：直连网站本来就要解析到国内 CDN，又快又准")
out.append("  default-nameserver: [223.5.5.5, 1.12.12.12]")
out.append("  proxy-server-nameserver: [223.5.5.5, 1.12.12.12]")
out.append("  nameserver:")
out.append("  - https://1.1.1.1/dns-query#🚀 节点选择")
out.append("  - https://8.8.8.8/dns-query#🚀 节点选择")
out.append("  nameserver-policy:")
out.append("    +.ts.net: [100.100.100.100]")
out.append('    "geosite:cn": [223.5.5.5, 119.29.29.29]')
out.append('    "geosite:private": [223.5.5.5, 119.29.29.29]')
for d in ["bilibili.com", "hdslb.com", "bilivideo.com", "biliapi.net", "biliapi.com"]:
    out.append('    "+.%s": [223.5.5.5, 119.29.29.29]' % d)
out.append("  direct-nameserver: [223.5.5.5, 119.29.29.29]")

# 节点
out.append("proxies:")
for n in nodes:
    out.append("- name: %s" % n["name"])
    if n["type"] == "vless":
        out.append("  type: vless")
        out.append("  server: %s" % n["server"])
        out.append("  port: %s" % n["port"])
        out.append("  uuid: %s" % n["uuid"])
        out.append("  tls: true")
        out.append("  servername: %s" % n["sni"])
        out.append("  reality-opts:")
        out.append("    public-key: %s" % n["public_key"])
        out.append("    short-id: %s" % n["short_id"])
        out.append("  client-fingerprint: chrome")
        out.append("  flow: xtls-rprx-vision")
        out.append("  udp: true")
    else:
        out.append("  type: hysteria2")
        out.append("  server: %s" % n["server"])
        out.append("  port: %s" % n["port"])
        out.append("  password: %s" % n["password"])
        out.append("  obfs: salamander")
        out.append("  obfs-password: %s" % n["obfs_password"])
        out.append("  sni: %s" % n["sni"])
        out.append("  skip-cert-verify: false")
        out.append("  fingerprint: %s" % n["fingerprint"])
        out.append("  up: %s Mbps" % n["up"])
        out.append("  down: %s Mbps" % n["down"])

# 策略组
out.append("proxy-groups:")
out.append("- name: 🚀 节点选择")
out.append("  type: select")
out.append("  proxies:")
for name in names:
    out.append("  - %s" % name)
out.append("- name: 🎥 WebRTC")
out.append("  type: select")
out.append("  proxies:")
out.append("  - REJECT")
out.append("  - DIRECT")
for group in ["🐱 GitHub", "🇬 Google", "📹 YouTube", "🤖 Claude"]:
    out.append("- name: %s" % group)
    out.append("  type: select")
    out.append("  proxies:")
    out.append("  - 🚀 节点选择")
    for name in names:
        out.append("  - %s" % name)
    out.append("  - DIRECT")

# 规则：白名单直连，其余全部代理
out.append("rules:")
out.append("- DST-PORT,3478/3479/3480/5349/19302/19305/19307,REJECT")
for n in nodes:
    if ":" in n["server"]:
        out.append("- IP-CIDR6,%s/128,DIRECT,no-resolve" % n["server"])
    else:
        out.append("- IP-CIDR,%s/32,DIRECT,no-resolve" % n["server"])
for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]:
    out.append("- IP-CIDR,%s,DIRECT,no-resolve" % cidr)
for d in whitelist:
    out.append("- DOMAIN-SUFFIX,%s,DIRECT" % d)
out.append("- DOMAIN-SUFFIX,gov.cn,DIRECT")
out.append("- DOMAIN-SUFFIX,edu.cn,DIRECT")
for d in ["weixin.qq.com", "wx.qq.com", "wechat.com", "qq.com", "tenpay.com",
          "alipay.com", "alipay.cn", "alipayobjects.com", "alipayplus.com"]:
    out.append("- DOMAIN-SUFFIX,%s,DIRECT" % d)
out.append("- GEOSITE,category-ads-all,REJECT")
out.append("- GEOSITE,anthropic,🤖 Claude")
for d in ["anthropic.com", "claude.ai", "claude.com", "claude.dev", "clau.de",
          "claudemcpclient.com", "claudemcpcontent.com", "claudeusercontent.com"]:
    out.append("- DOMAIN-SUFFIX,%s,🤖 Claude" % d)
out.append("- GEOSITE,github,🐱 GitHub")
out.append("- GEOSITE,youtube,📹 YouTube")
out.append("- GEOSITE,google,🇬 Google")
out.append("- IP-CIDR,127.0.0.0/8,DIRECT,no-resolve")
out.append("- GEOIP,CN,DIRECT,no-resolve")
out.append("- GEOSITE,cn,DIRECT")
out.append("- GEOIP,CN,DIRECT,no-resolve")
out.append("- MATCH,🚀 节点选择")

with open(out_path, "w") as f:
    f.write("\n".join(out) + "\n")
print("已生成 %d 个节点的 Clash 配置" % len(nodes))
PYEOF
  echo "Clash 配置已生成：$out"
  echo "用法：下载到电脑，在 Clash Verge 里新建配置 → 导入本地文件，选它"
  echo "白名单想加域名：改 sb.sh 顶部的 WHITELIST_DOMAINS，重新跑 ./sb.sh clash"
}

# ---------- 订阅 ----------
# 生成订阅文件（节点变了就重新生成；nginx 直接读这些文件，不用重启）：
#   subscribe/clash          Clash 完整配置（gen_clash 的输出）
#   subscribe/shadowrocket   base64 编码的节点链接（Shadowrocket / Throne / v2rayN 通用）
#   subscribe/sing-box       sing-box 客户端配置（SFM / SFI / SFA 导入用）
#   subscribe/proxies        仅 proxies 段
# 订阅地址：http://<服务器IP>:<SUBSCRIBE_PORT>/<TOKEN>/auto
#   Clash Verge / Shadowrocket 里用这个地址当订阅链接；/auto 按 UA 自动分流。
gen_subscribe() {
  init_config
  local subdir="$SUBSCRIBE_DIR"
  mkdir -p "$subdir"
  # token：第一次生成一个 UUID，之后一直用它（换节点不换订阅地址）
  local token
  if [ -f "$SUBSCRIBE_TOKEN_FILE" ]; then
    token=$(cat "$SUBSCRIBE_TOKEN_FILE")
  else
    token=$(sing-box generate uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    echo "$token" > "$SUBSCRIBE_TOKEN_FILE"
  fi
  # 1) clash：复用 gen_clash 的输出
  gen_clash >/dev/null
  cp "$SB_STATE_DIR/clash.yaml" "$subdir/clash"
  # 2) shadowrocket / sing-box / proxies：用 nodes.json 生成
  python3 - "$NODES" "$subdir" <<'PYEOF'
import base64, json, sys, urllib.parse

nodes_path, subdir = sys.argv[1], sys.argv[2]
with open(nodes_path) as f:
    nodes = json.load(f)
if not nodes:
    print("还没有节点。先用 add-vless 或 add-hy2 添加一个。")
    sys.exit(1)

def node_uri(n):
    name = urllib.parse.quote(n["name"])
    host = "[%s]" % n["server"] if ":" in n["server"] else n["server"]
    if n["type"] == "vless":
        return ("vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision"
                "&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s"
                % (n["uuid"], host, n["port"], n["sni"],
                   n["public_key"], n["short_id"], name))
    return ("hysteria2://%s@%s:%s?obfs=salamander&obfs-password=%s"
            "&sni=%s&insecure=1#%s"
            % (n["password"], host, n["port"],
               n["obfs_password"], n["sni"], name))

uris = [node_uri(n) for n in nodes]
# shadowrocket：base64 编码的链接列表（Shadowrocket / Throne / v2rayN 通用）
with open(subdir + "/shadowrocket", "w") as f:
    f.write(base64.b64encode("\n".join(uris).encode()).decode() + "\n")

# proxies：仅 Clash 的 proxies 段
out = ["proxies:"]
for n in nodes:
    out.append("- name: %s" % n["name"])
    if n["type"] == "vless":
        out += ["  type: vless", "  server: %s" % n["server"],
                "  port: %s" % n["port"], "  uuid: %s" % n["uuid"],
                "  tls: true", "  servername: %s" % n["sni"],
                "  reality-opts:", "    public-key: %s" % n["public_key"],
                "    short-id: %s" % n["short_id"],
                "  client-fingerprint: chrome",
                "  flow: xtls-rprx-vision", "  udp: true"]
    else:
        out += ["  type: hysteria2", "  server: %s" % n["server"],
                "  port: %s" % n["port"], "  password: %s" % n["password"],
                "  obfs: salamander",
                "  obfs-password: %s" % n["obfs_password"],
                "  sni: %s" % n["sni"], "  skip-cert-verify: false",
                "  fingerprint: %s" % n["fingerprint"],
                "  up: %s Mbps" % n["up"], "  down: %s Mbps" % n["down"]]
with open(subdir + "/proxies", "w") as f:
    f.write("\n".join(out) + "\n")

# sing-box 客户端配置（SFM / SFI / SFA 导入用）
outbounds, tags = [], []
for n in nodes:
    if n["type"] == "vless":
        outbounds.append({
            "type": "vless", "tag": n["name"],
            "server": n["server"], "server_port": n["port"],
            "uuid": n["uuid"], "flow": "xtls-rprx-vision",
            "tls": {"enabled": True, "server_name": n["sni"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True,
                                "public_key": n["public_key"],
                                "short_id": n["short_id"]}}
        })
    else:
        outbounds.append({
            "type": "hysteria2", "tag": n["name"],
            "server": n["server"], "server_port": n["port"],
            "password": n["password"],
            "tls": {"enabled": True, "server_name": n["sni"], "insecure": True},
            "obfs": {"type": "salamander", "password": n["obfs_password"]}
        })
    tags.append(n["name"])
outbounds.append({"type": "selector", "tag": "🚀 节点选择",
                  "outbounds": tags + ["direct"]})
outbounds.append({"type": "direct", "tag": "direct"})
client = {
    "log": {"level": "info", "timestamp": True},
    "dns": {"servers": [{"tag": "google", "type": "tls", "server": "8.8.8.8"},
                        {"tag": "local", "type": "https", "server": "223.5.5.5"}],
            "strategy": "prefer_ipv4"},
    "inbounds": [{"type": "mixed", "tag": "mixed-in",
                  "listen": "127.0.0.1", "listen_port": 1080}],
    "outbounds": outbounds,
    "route": {"final": "🚀 节点选择", "default_domain_resolver": "local"}
}
with open(subdir + "/sing-box", "w") as f:
    json.dump(client, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("订阅文件已生成：clash / shadowrocket / sing-box / proxies")
PYEOF
  local ip
  ip=$(server_ip)
  echo "订阅已生成：$subdir"
  if [ -n "$ip" ]; then
    echo "订阅地址：http://$(fmt_hostport "$ip" "$SUBSCRIBE_PORT")/$token/auto"
    echo "（Clash Verge / Shadowrocket 里用这个地址；换节点后重新跑 ./sb.sh sub 刷新）"
  else
    echo "拿不到服务器公网 IP，订阅地址里的 IP 自己填：http://<服务器IP>:$SUBSCRIBE_PORT/$token/auto"
  fi
}

# 订阅服务（nginx）：按客户端 UA 分流订阅文件，独立 systemd 服务。
# 只在第一次或配置变了时需要跑；订阅文件本身改了不用重启 nginx。
setup_subscribe_nginx() {
  local token nginx_bin
  token=$(cat "$SUBSCRIBE_TOKEN_FILE")
  nginx_bin=$(command -v nginx || true)
  # 配置文件先写出来，测试模式也能检查模板
  cat > "$SUBSCRIBE_NGINX_CONF" <<EOF
# sb.sh 订阅服务（nginx）：按客户端 UA 分流订阅文件
# 订阅地址：http://<服务器IP>:$SUBSCRIBE_PORT/$token/auto
user  root;
worker_processes  auto;
error_log  $SB_STATE_DIR/nginx-error.log;
pid        /var/run/sb-subscribe-nginx.pid;
events {
    worker_connections  1024;
}
http {
  map \$http_user_agent \$subfile {
    default                    /;
    ~*clash                    /clash;
    ~*ShadowRocket             /shadowrocket;
    ~*Throne|Neko              /shadowrocket;
    ~*v2rayN                   /shadowrocket;
    ~*SFM|SFI|SFA              /sing-box;
  }
  access_log  /dev/null;
  sendfile        on;
  keepalive_timeout  65;
  server {
    listen $SUBSCRIBE_PORT;
    listen [::]:$SUBSCRIBE_PORT;
    server_name localhost;
    location ~ ^/$token/auto {
      default_type 'text/plain; charset=utf-8';
      alias $SUBSCRIBE_DIR/\$subfile;
    }
    location ~ ^/$token/(.*) {
      default_type 'text/plain; charset=utf-8';
      alias $SUBSCRIBE_DIR/\$1;
    }
  }
}
EOF
  if [ -n "${SB_TEST_DIR:-}" ]; then
    echo "[测试模式] 跳过 nginx 安装 / systemd，配置文件已写到 $SUBSCRIBE_NGINX_CONF"
    return 0
  fi
  if [ -z "$nginx_bin" ]; then
    echo "正在安装 nginx……"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq && apt-get install -y -qq nginx
    elif command -v yum >/dev/null 2>&1; then
      yum install -y -q nginx
    else
      echo "装不了 nginx：没有 apt-get/yum，请手动安装后重新跑 ./sb.sh sub" >&2
      exit 1
    fi
    nginx_bin=$(command -v nginx)
  fi
  "$nginx_bin" -c "$SUBSCRIBE_NGINX_CONF" -t
  cat > /etc/systemd/system/sb-subscribe.service <<EOF
[Unit]
Description=sb.sh 订阅服务 (nginx)
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sb-subscribe-nginx.pid
ExecStart=$nginx_bin -c $SUBSCRIBE_NGINX_CONF
ExecReload=$nginx_bin -c $SUBSCRIBE_NGINX_CONF -s reload
ExecStop=$nginx_bin -c $SUBSCRIBE_NGINX_CONF -s stop

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now sb-subscribe
  systemctl restart sb-subscribe
  allow_port "$SUBSCRIBE_PORT" tcp
  echo "订阅服务已启动，端口 $SUBSCRIBE_PORT"
}

# ---------- 服务管理 ----------

do_status() {
  if [ -n "${SB_TEST_DIR:-}" ]; then
    echo "[测试模式] 跳过 systemctl"
    sing-box check -c "$CONFIG"
    return 0
  fi
  systemctl status sing-box --no-pager | head -n 20
}

do_restart() {
  if [ -n "${SB_TEST_DIR:-}" ]; then
    echo "[测试模式] 跳过 systemctl"
    return 0
  fi
  systemctl restart sing-box && echo "sing-box 已重启"
}

do_logs() {
  if [ -n "${SB_TEST_DIR:-}" ]; then
    echo "[测试模式] 跳过 journalctl"
    return 0
  fi
  journalctl -u sing-box -n 50 --no-pager
}

do_uninstall() {
  read -r -p "确定卸载 sing-box 并删除全部配置和节点记录？(y/N) " ans
  case "$ans" in
    y|Y)
      if [ -z "${SB_TEST_DIR:-}" ]; then
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box.service
        rm -f /usr/local/bin/sing-box
        systemctl daemon-reload
      fi
      rm -rf "$SB_BASE" "$SB_STATE_DIR"
      echo "已卸载"
      ;;
    *) echo "已取消" ;;
  esac
}

# ---------- 菜单 ----------

show_menu() {
  while true; do
    echo ""
    echo "========== sing-box 轻量管理 =========="
    echo "1) 添加 VLESS + Reality 节点"
    echo "2) 添加 Hysteria2 节点（Salamander 混淆）"
    echo "3) 查看全部节点（链接 + Clash 配置）"
    echo "4) 生成 Clash 配置文件（白名单直连，其余代理）"
    echo "5) 查看运行状态"
    echo "6) 重启 sing-box"
    echo "7) 查看日志"
    echo "8) 卸载"
    echo "9) 生成订阅并启动订阅服务"
    echo "10) 查看并应用服务端拦截规则（微信 / 支付宝 / 银行 / 政府）"
    echo "11) 改节点 IP（v4 / v6 / auto / 指定 IP）"
    echo "0) 退出"
    echo "======================================"
    read -r -p "选一个 [0-11]: " choice
    case "$choice" in
      1) read -r -p "端口 [443]: " p; read -r -p "伪装域名 [www.microsoft.com]: " s; read -r -p "节点名 [VLESS-Reality]: " n; read -r -p "IP（回车=当前偏好，v6 / v4）: " a
         if [ -n "$a" ]; then add_vless --port "${p:-443}" --sni "${s:-www.microsoft.com}" --name "${n:-VLESS-Reality}" --ip "$a"; else add_vless --port "${p:-443}" --sni "${s:-www.microsoft.com}" --name "${n:-VLESS-Reality}"; fi ;;
      2) read -r -p "端口 [443]: " p; read -r -p "节点名 [Hy2]: " n; read -r -p "IP（回车=当前偏好，v6 / v4）: " a
         if [ -n "$a" ]; then add_hy2 --port "${p:-443}" --name "${n:-Hy2}" --ip "$a"; else add_hy2 --port "${p:-443}" --name "${n:-Hy2}"; fi ;;
      3) list_nodes ;;
      4) gen_clash ;;
      5) do_status ;;
      6) do_restart ;;
      7) do_logs ;;
      8) do_uninstall ;;
      9) gen_subscribe; setup_subscribe_nginx ;;
      10) show_reject; init_config; reload_config; echo "服务端拦截规则已应用" ;;
      11) cur=$(cat "$SB_STATE_DIR/ip_mode" 2>/dev/null || echo auto)
          read -r -p "改节点 IP（v4 / v6 / auto / 具体 IP，当前 $cur，回车取消）: " a
          [ -n "$a" ] && set_ip "$a" ;;
      0) exit 0 ;;
      *) echo "没有这个选项" ;;
    esac
  done
}

# ---------- 入口 ----------

case "${1:-menu}" in
  menu)      show_menu ;;
  add-vless) shift; add_vless "$@" ;;
  add-hy2)   shift; add_hy2 "$@" ;;
  list)      list_nodes ;;
  clash)     gen_clash ;;
  sub)       gen_subscribe; setup_subscribe_nginx ;;
  reject)    show_reject; init_config; reload_config; echo "服务端拦截规则已应用" ;;
  set-ip)    shift; set_ip "$@" ;;
  status)    do_status ;;
  restart)   do_restart ;;
  logs)      do_logs ;;
  uninstall) do_uninstall ;;
  *) echo "用法：$0 [menu|add-vless|add-hy2|list|clash|sub|reject|set-ip|status|restart|logs|uninstall]" >&2; exit 1 ;;
esac
