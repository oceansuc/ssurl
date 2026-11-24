# Cloudflare Worker Short URL

**一个基于 Cloudflare Workers + Workers KV 的轻量级短链接服务。**

无需购买 VPS，无需独立数据库，无需 Docker。使用 Cloudflare Workers 提供短链接生成、跳转、管理后台、Turnstile 人机验证和边缘缓存。

当前版本：**v2.6.0**
![admin.png](https://img.disue.com/image/6cf9bf46a962b616f6ef87c12343de0e)

![home.png](https://img.disue.com/image/d5c685346ceae55c52ca277d342b1458)

## ✨ 功能特性

### 短链接功能

- 自动生成随机短码（10 位密码学安全随机字符）。
- 支持自定义短码。
- 自动检测短码冲突。
- 支持相同 URL 的重复检测和短链复用。
- 支持永久有效、1 天、30 天三种有效期。
- HTTP / HTTPS URL 自动补全和校验。
- 支持原有短链接继续访问。

### 安全防护

- 管理后台采用 HttpOnly + Secure + SameSite Cookie 会话认证。
- HMAC-SHA256 签名和会话过期验证。
- 不再向浏览器返回 Turnstile Secret。
- 支持 Cloudflare Worker Secret 管理敏感信息。
- 修复管理后台存储型 XSS 风险。
- 自定义短码格式校验和系统保留键保护。
- 请求体大小限制和参数校验。
- 限制非 HTTP / HTTPS 跳转地址。
- 统一错误处理，不向访客暴露内部堆栈。
- CSP、Referrer-Policy、X-Content-Type-Options 等安全响应头。

### Turnstile 验证码

支持在管理后台独立开启或关闭 Cloudflare Turnstile。

- 可选功能，关闭时不需要配置验证码密钥。
- SiteKey 保存在 KV。
- SecretKey 保存在 Cloudflare Worker Secret。
- 兼容旧版 KV 中的 `SYS_SS`。
- 验证 Token、Hostname 和 Action。
- 支持 Token 过期和重新验证。

### 管理后台

现代化响应式管理界面，适配电脑和手机。

- 管理员登录和退出。
- HttpOnly Cookie 会话。
- 短链接列表及 KV 游标分页。
- 搜索短码、目标域名和 URL。
- 永久有效、限时有效、即将到期等筛选。
- 短码、创建时间、到期时间和域名排序。
- 一键复制完整短链接。
- 新标签页打开原始目标 URL。
- 删除短链接及缓存清理。
- 创建时间和过期时间显示。
- Turnstile 配置管理。

说明：搜索、筛选和排序针对当前已加载页，不扫描整个 KV Namespace。历史记录没有创建时间 metadata 时显示“未记录”。

## 🚀 技术架构

| 组件 | 技术 | 用途 |
|---|---|---|
| 运行环境 | Cloudflare Workers | 处理 HTTP 请求 |
| 数据存储 | Cloudflare Workers KV | 保存短链接及索引 |
| 边缘缓存 | Cloudflare Workers Cache API | 缓存 302 跳转 |
| 身份认证 | Web Crypto API / HMAC-SHA256 | 管理员会话 |
| 人机验证 | Cloudflare Turnstile | 防止自动化滥用 |
| 限流 | Workers Rate Limiting API / Cloudflare WAF | 请求频率控制 |
| 缓存清理 | Cloudflare Cache Purge API | 清理短链缓存 |

### 短链数据结构

继续使用原有 KV Namespace，不需要迁移历史记录。

```text
LINKS
│
├── abc123
│   └── https://example.com
│
├── 123abc
│   └── https://github.com
│
├── SHA256(URL)
│   └── abc123
│
├── SYS_CE
│   └── true / false
│
├── SYS_SK
│   └── Turnstile SiteKey
│
└── SYS_SS
    └── Legacy Turnstile Secret
```

其中：

- 短码对应原始目标 URL。
- SHA256(URL) 对应短码，用于自动生成短链时去重。
- `SYS_CE` 保存 Turnstile 开关。
- `SYS_SK` 保存公开 SiteKey。
- `SYS_SS` 是旧版本 Secret 兼容数据。

新版优先读取 Worker Secret `TURNSTILE_SECRET`，仅在没有配置新 Secret 时读取旧版 `SYS_SS`。

**不要删除原来的 KV Namespace，也不要手动清空历史记录。**

## ⚡ 24 小时边缘缓存

使用 Cloudflare Workers Cache API 缓存短链接 302 响应，减少重复 KV 读取。

缓存策略：

| 链接类型 | 缓存时间 |
|---|---|
| 永久有效 | 最长 24 小时 |
| 1 天有效 | 不超过剩余有效期 |
| 30 天有效 | 最长 24 小时 |
| 过期链接 | 不缓存 |
| 无法确认有效期的旧记录 | 不缓存 |

缓存行为：

1. 请求短链接。
2. 查询当前 Cloudflare 数据中心的 Cache API。
3. 缓存命中，直接返回 302。
4. 缓存未命中，读取 Workers KV。
5. 确认短链有效期。
6. 将符合条件的跳转响应缓存，最长 24 小时。

响应调试头：

```text
X-ShortURL-Cache: HIT
X-ShortURL-Cache: MISS
X-ShortURL-Cache: BYPASS-LEGACY
```

删除短链时：

- 删除当前数据中心的 Cache API 缓存。
- 删除 KV 中的短链记录。
- 清理对应 SHA256 去重索引。
- 配置全局缓存清理后，向 Cloudflare Cache Purge API 发送清理请求。

**缓存说明：**

Workers Cache API 是数据中心本地缓存，不是全球共享缓存。缓存命中仍会执行 Worker，但可以减少 KV 读取。全局 Cache-Tag Purge 依赖额外的 Cloudflare API Token。

旧版缓存没有新版本的 Cache-Tag，升级时还需要考虑原有缓存的过渡期。

参考：
- [Cloudflare Workers Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/)
- [How the Cache works](https://developers.cloudflare.com/workers/reference/how-the-cache-works/)
- [Cloudflare Cache Purge](https://developers.cloudflare.com/cache/how-to/purge-cache/)

## 📦 部署要求

只需要：

- 一个 Cloudflare 账户。
- 一个 Cloudflare Worker。
- 一个现有或新建的 KV Namespace。
- 一个绑定到 Worker 的域名（推荐）。

无需 VPS、Docker、数据库服务器或额外后台程序。

### 1. 创建 KV Namespace

进入：

```text
Cloudflare Dashboard
→ Workers & Pages
→ KV
→ Create namespace
```

建议命名：

```text
SHORT_URL_LINKS
```

如果是从 v2.4 / v2.5 升级，必须继续使用原来的 KV Namespace。

### 2. 创建 Worker

进入：

```text
Cloudflare Dashboard
→ Workers & Pages
→ Create Worker
```

建议 Worker 名称：

```text
short-url
```

将项目 Worker 源码粘贴到编辑器并保存。

### 3. 配置 KV Binding

进入：

```text
Worker
→ Settings
→ Bindings
→ Add
→ KV Namespace
```

绑定名称必须是：

```text
LINKS
```

选择对应的 KV Namespace。

### 4. 配置 Worker Secrets

进入：

```text
Worker
→ Settings
→ Variables and Secrets
```

添加：

| 名称 | 类型 | 是否必需 |
|---|---|---|
| `ADMIN_PASS` | Secret | 必须 |
| `TURNSTILE_SECRET` | Secret | 可选 |
| `CF_PURGE_TOKEN` | Secret | 可选 |

`ADMIN_PASS` 用于管理员密码验证和 HMAC 会话签名。

`TURNSTILE_SECRET` 用于后端验证码验证。

`CF_PURGE_TOKEN` 用于调用 Cloudflare 缓存清理 API。

不要将 Secret 写入 JavaScript 源码、GitHub 仓库或公开环境变量。

### 5. 配置普通变量

| 名称 | 类型 | 是否必需 |
|---|---|---|
| `CF_ZONE_ID` | Variable | 可选 |

填写短链接域名所属 Cloudflare Zone ID。

例如短链域名：

```text
go.example.com
```

如果 `CF_PURGE_TOKEN` 和 `CF_ZONE_ID` 均已配置，删除短链时才会尝试调用 Cloudflare 全局缓存清理。

### 6. 绑定自定义域名

进入：

```text
Worker
→ Settings
→ Domains & Routes
→ Add
→ Custom Domain
```

例如：

```text
go.example.com
```

确保域名使用 Cloudflare DNS，并启用 HTTPS。

部署成功后：

```text
https://go.example.com/
```

访问短链生成页面。

```text
https://go.example.com/admin
```

访问管理后台。

## 🔐 可选功能配置

### Turnstile 验证码

Turnstile 是可选功能，可以在管理后台开启或关闭。

开启步骤：

1. 登录 Cloudflare。
2. 进入 Turnstile。
3. 创建 Widget。
4. 设置允许访问的域名。
5. 复制 SiteKey。
6. 将 SiteKey 填入短链管理后台。
7. 在 Worker Secrets 添加 `TURNSTILE_SECRET`。
8. 在后台开启 Turnstile 并保存。

密钥用途：

| 配置 | 作用 | 存放位置 |
|---|---|---|
| SiteKey | 浏览器显示验证码组件 | KV：`SYS_SK` |
| SecretKey | 后端验证 Token | Worker Secret：`TURNSTILE_SECRET` |

Secret 不会返回给浏览器。

关闭验证码时，不需要配置 SiteKey 或 SecretKey。

### Cloudflare 全局缓存清理

这是可选功能。

需要同时配置：

```text
CF_PURGE_TOKEN
CF_ZONE_ID
```

API Token 最小权限建议：

```text
Zone
Cache Purge
Purge
```

仅授权需要管理的 Zone。

没有配置时，系统仍能正常创建、跳转和删除短链，但不执行 API 全局缓存清理。

### 创建接口限流

可选配置 Workers Rate Limiting Binding：

```text
CREATE_LIMITER
```

建议初始值：

```text
limit: 20
period: 60
```

表示每个统计键每 60 秒允许 20 次调用。

### 管理员登录限流

可选配置：

```text
ADMIN_LOGIN_LIMITER
```

建议初始值：

```text
limit: 5
period: 60
```

表示每个统计键每 60 秒允许 5 次登录尝试。

如果不配置这两个 Binding，相关代码内限流检查会跳过，不影响其他功能。

**注意：** Workers Rate Limiting 属于近似统计，分别在 Cloudflare 各数据中心生效，不是严格的全球统一计数。也可以使用 Cloudflare WAF Rate Limiting Rules 实施额外保护。

参考：
- [Workers Rate Limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
- [Cloudflare Rate Limiting Rules](https://developers.cloudflare.com/waf/rate-limiting-rules/)

## 🖥️ 管理后台使用

访问：

```text
https://go.example.com/admin
```

使用 `ADMIN_PASS` 登录。

管理后台支持：

| 功能 | 说明 |
|---|---|
| 链接列表 | 查看当前页短链 |
| 搜索 | 搜索短码、域名和目标 URL |
| 筛选 | 全部、永久、限时、即将到期、已到期 |
| 排序 | 短码、创建时间、到期时间、域名 |
| 分页 | 使用 KV Cursor |
| 复制 | 复制完整短链接 |
| 打开 | 在新标签页访问原始目标 |
| 删除 | 删除短链和关联去重索引 |
| 验证码设置 | 开启或关闭 Turnstile |

统计数据只针对当前加载页，不代表整个 KV Namespace 的总量。

历史链接如果没有创建时间 metadata，会显示：

```text
创建：未记录
```

不会为旧数据伪造时间。

## 🔌 API 接口

### 创建短链

```http
POST /api/create
Content-Type: application/json
```

请求：

```json
{
  "url": "https://example.com",
  "key": "",
  "expire": "0",
  "token": ""
}
```

参数说明：

| 参数 | 说明 |
|---|---|
| `url` | 原始目标 URL |
| `key` | 自定义短码，留空自动生成 |
| `expire` | 0、86400 或 2592000 |
| `token` | Turnstile Token，验证码开启时必填 |

成功响应：

```json
{
  "key": "/Abc1234567",
  "reused": false
}
```

重复 URL 使用现有短链时：

```json
{
  "key": "/Abc1234567",
  "reused": true
}
```

### 获取前台配置

```http
GET /api/ui-cfg
```

返回公开配置：

```json
{
  "ce": "true",
  "sk": "YOUR_SITE_KEY"
}
```

不会返回 SecretKey。

### 管理后台登录

```http
POST /admin/api/login
Content-Type: application/json
```

```json
{
  "password": "YOUR_ADMIN_PASSWORD"
}
```

成功后设置 HttpOnly 会话 Cookie。

### 管理后台退出

```http
POST /admin/api/logout
```

清除管理员会话 Cookie。

### 获取短链列表

```http
GET /admin/api/all
```

下一页：

```http
GET /admin/api/all?cursor=CURSOR
```

需要有效管理员会话。

### 保存验证码配置

```http
POST /admin/api/config
Content-Type: application/json
```

```json
{
  "ce": true,
  "sk": "YOUR_SITE_KEY"
}
```

### 删除短链

```http
POST /admin/api/delete
Content-Type: application/json
```

```json
{
  "key": "Abc1234567"
}
```

管理接口不提供跨域开放权限，使用同源会话认证。

## 🔄 升级与数据兼容

v2.6.0 保留 v2.4 / v2.5 的核心 KV 数据结构。

| 原有数据 | 处理方式 |
|---|---|
| 短码 → 原始 URL | 保留 |
| SHA256(URL) → 短码 | 兼容读取 |
| `SYS_CE` | 保留 |
| `SYS_SK` | 保留 |
| `SYS_SS` | 兼容读取 |
| 原有短链接 | 不迁移、不重新生成 |

新版自动生成短链时，会兼容查询旧版本的原始 URL SHA256 索引，以及规范化 URL 的 SHA256 索引。

### 升级步骤

1. 备份原 v2.4 / v2.5 Worker 源码。
2. 备份现有 KV Namespace 数据。
3. 保留原 `LINKS` 绑定。
4. 保留原 `ADMIN_PASS`。
5. 根据需求添加可选 Worker Secrets。
6. 替换 Worker 源码并部署。
7. 验证旧短链、管理员登录、验证码和新短链创建。
8. 测试缓存命中及短链删除。
9. 检查无异常后正式切换。

**不要删除原 KV Namespace，也不要清空历史数据。**

## ⚠️ 已知限制

1. Workers KV 是最终一致性存储，跨地区更新可能存在延迟。
2. KV 不支持原子创建，因此单纯使用读取检查和写入不能彻底杜绝并发自定义短码竞争。
3. Workers Cache API 是数据中心本地缓存，不具备全球共享缓存和 Tiered Cache 能力。
4. 删除短链后的全球缓存清理依赖可选的 Cloudflare API Token。
5. v2.4 的历史缓存没有新版本的 Cache-Tag，升级后可能需要等待原缓存过期。
6. 历史短链如果没有 metadata，无法准确还原创建时间。
7. 后台搜索、筛选和排序只作用于当前加载页。
8. Rate Limiting Binding 是近似计数，不能代替严格的全局限流系统。
9. 不配置限流 Binding 时，建议在 Cloudflare WAF 层配置基础防滥用规则。

## 🔒 安全建议

- 使用高强度管理员密码。
- 不要在公开仓库提交任何 Secret。
- 保持 Worker Secret 与代码分离。
- Turnstile Secret 不应返回浏览器。
- 建议启用 Turnstile 防止自动化滥用。
- 建议为 `/api/create` 和管理员登录配置限流。
- 定期检查 Worker Logs 和 KV 使用量。
- 升级前备份 KV 数据。
- 如果旧版管理员密码曾泄露，及时轮换 `ADMIN_PASS`。
- 完成 v2.6 升级后，不建议继续使用旧版 `Authorization` 明文密码管理方式。

## 📚 官方文档

- [Cloudflare Workers](https://developers.cloudflare.com/workers/)
- [Workers KV](https://developers.cloudflare.com/kv/)
- [Workers Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/)
- [Workers Rate Limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)
- [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
- [Cloudflare Cache Purge API](https://developers.cloudflare.com/api/resources/cache/methods/purge/)

## 📄 License

请根据项目发布者的实际授权协议添加许可证。当前 README 不预设项目许可证。
