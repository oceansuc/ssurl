# Cloudflare Worker 短链接生成器 (带管理后台)

这是一个基于 Cloudflare Workers 和 KV 存储的轻量级、自托管短链接服务。

### ✨ 项目特性
- **内置 UI**：单文件架构，自带响应式生成页面和管理后台。
- **管理后台**：支持查看链接列表、删除失效链接、动态配置 Turnstile 验证码。
- **安全加固**：集成 Cloudflare Turnstile，支持“一次验证，多次使用”逻辑。
- **零成本运维**：利用 Cloudflare 免费额度，即可拥有极速的全球访问体验。

### 🛠️ 快速部署
1. **创建 KV**：在 Cloudflare 控制台创建一个名为 `LINKS` 的 KV 命名空间。
2. **绑定变量**：在 Worker 设置中将变量 `LINKS` 绑定到刚才创建的命名空间。
3. **上传代码**：将 `ssurl.js` 的内容复制到 Worker 编辑器中。
4. **修改密码**：修改代码顶部 `INTERNAL_CONFIG` 中的 `admin_pass`。
5. **设置域名**：绑定你自己的自定义域名。

### 📖 使用说明
- **首页**：`https://你的域名/` - 生成短链接。
- **管理页**：`https://你的域名/admin` - 管理链接与系统设置。

### 🤝 贡献与支持
欢迎提交 Issue 或 Pull Request 来改进本项目！
