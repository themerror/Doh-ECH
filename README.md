# DOH-ECH — 精简 DoH Worker

基于 Cloudflare Worker 的个人 DNS-over-HTTPS 服务器，支持 ECH 注入、增强 HTTPS RR、双上游竞速。

---

## 警告

本项目由 AI 生成，仅供学习研究，**不得用于非法用途**。使用者需遵守当地法律法规，后果自负。

---

## 路由说明

| 路径 | 说明 |
|------|------|
| `/` | 前端测试页面（域名输入、类型选择、参数配置） |
| `/ech` | DoH 端点（增强模式 + ECH 注入） |
| `/doh` | DoH 端点（与 `/ech` 功能一致） |
| `/api/query` | JSON API（`?domain=xxx&type=A`） |
| `/log` | 运行状态页面 |

---

## 项目特性

- **DoH 服务** — GET/POST 标准 DNS-over-HTTPS，兼容 Chrome/Firefox/代理客户端
- **ECH 注入** — 从指定域名的 HTTPS 记录动态获取 ECH 公钥，注入响应中加密 SNI
- **双上游竞速** — AdGuard DNS + Cloudflare DNS 并发查询，取最快响应（Promise.any）
- **增强模式** — 内置 + 自定义规则，精细控制每个域名的 DNS 应答（IP hints、ALPN、记录屏蔽）
- **Edge 缓存** — Cloudflare Cache API 缓存DNS 结果（A/AAAA 300s，HTTPS 600s，ECH 3600s）
- **ECS 就近解析** — 自动获取客户端真实 IP 构造 EDNS Client Subnet

---

## 部署

### Cloudflare Dashboard（推荐）

1. 打开 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Workers & Pages**
2. 创建 Worker → 粘贴 `_worker.js` 全部内容 → **部署**
3. 绑定自定义域名或使用分配的 `*.workers.dev` 域名

### Wrangler CLI

```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

---

## 使用

### 浏览器（推荐）

Chrome / Firefox 设置 → 隐私与安全 → 安全 DNS → 自定义：

```
https://your-domain.workers.dev/ech
```

默认启用 ECH 注入 + QUIC 优先（`alpn=h3,h2`）+ 本机 ECS 就近解析，无需额外参数。

### 代理工具

将 CF 相关站点的 DoH 指向：

```
https://your-domain.workers.dev/ech
```

---

## 参数

所有参数均支持 **URL 查询字符串** 或 **HTTP 请求头** 传入。

### ECH

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `ech` | `cloudflare-ech.com` | ECH 公钥来源域名，从该域名的 HTTPS 记录中提取 |

### 增强模式

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `enhance` | `rule` | `off` — 关闭；`rule` — 仅匹配规则的域名生效；`full` — 所有域名生效 |
| `rules` | — | 自定义规则，格式见下方 |
| `alpn` | `h3,h2` | HTTPS 记录的 ALPN 列表（`h3` 优先 QUIC，`h2` 回退） |
| `mandatory` | `alpn` | 客户端必须理解的 HTTPS 参数 |

### 通用

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `clientIp` | 自动获取 | 自定义 ECS 地址（格式 `1.2.4.8`），影响上游 DNS 就近解析 |
| `shuffle` | `true` | 返回 IP 随机乱序 |

### 规则格式

```
rules=*.domain1,*domain2:ip1,ip2-noA-noAAAA
```

| 组成部分 | 说明 | 示例 |
|----------|------|------|
| 域名 | 支持通配符 `*.`，逗号分隔多个 | `*.google.com,google.com.hk` |
| IP 列表 | 可选，逗号分隔的 IPv4/IPv6 | `151.101.1.140,2001:db8::1` |
| `-noA` | 屏蔽 A（IPv4）记录 | |
| `-noAAAA` | 屏蔽 AAAA（IPv6）记录 | |

**示例**：

```
# 强制 Google 纯 IPv6，注入指定 IP 前缀
*.google.com,*.youtube.com:2001:4860:4827:7700::1,2001:4860:4827:7700::2-noA

# 屏蔽 Reddit 的 AAAA 记录（纯 IPv4）
*.reddit.com,*.redd.it:151.101.1.140,151.101.65.140-noAAAA

# 纯屏蔽，不注入 IP
*.domain.com::noA-noAAAA
```

### 请求头传参

```
X-Enhance: full
X-Alpn: h3
X-ECH: cloudflare-ech.com
X-ClientIP: 1.2.4.8
X-Rules: *.google.com::noA
```

---

## 内置规则

`BUILTIN_HINTS` 预设了多组规则（编辑 `_worker.js` 修改）：

| 规则组 | 效果 |
|--------|------|
| Google 服务 | `*.google.com`、`*.youtube.com` 等 → 注入 Google IPv6 前缀，屏蔽 A |
| Google 视频 | `*.googlevideo.com` → 纯 IPv6 |
| Google 静态 | `*.gstatic.com`、`*.ytimg.com` 等 → 注入 IPv6 前缀，屏蔽 A |
| GitHub hosts | 从 `raw.hellogithub.com/hosts.json` 拉取 IP |
| Meta 全家桶 | `*.facebook.com`、`*.instagram.com` 等 → 屏蔽 A |
| Wikipedia | `*.wikipedia.org` 等 → 屏蔽 A |
| Fastly CDN | Reddit、Imgur、StackOverflow、PyPI、DuckDuckGo、Medium、Pinterest 等 → 注入 Fastly IPv4 hints，屏蔽 AAAA |

---

## ECS 原理

```
客户端 → DoH 请求 → Cloudflare Edge（注入 CF-Connecting-IP）
                           ↓
                     Worker（读取 CF-Connecting-IP，构造 ECS）
                           ↓
                     上游 DNS（AdGuard / Cloudflare）
                           ↓
                     返回就近解析结果
```

部分客户端获取不到 `CF-Connecting-IP` 时，手动传入 `clientIp=1.2.4.8`。

---

## 注意事项

- **免费配额**：每日 10 万次子请求，缓存可降低 90% 以上的上游查询
- **ECH 有效期**：从 `ech` 指定域名动态获取，缓存 1 小时
- **上游隐私**：DNS 查询经过 AdGuard DNS 和 Cloudflare DNS 的 JSON API
