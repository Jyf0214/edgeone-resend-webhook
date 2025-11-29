# edgeone-resend-webhook
# 📧 Resend Webhook Forwarder (Multi-Platform)

<div align="center">

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Jyf0214/edgeone-resend-webhook&env=RESEND_API_KEY,WEBHOOK_SIGNING_SECRET,FROM_EMAIL,FORWARD_TO_EMAIL&project-name=resend-webhook-forwarder&repository-name=resend-webhook-forwarder)
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Jyf0214/edgeone-resend-webhook)

</div>

一个轻量级、安全且跨平台的 Webhook 端点解决方案。它可以接收 [Resend](https://resend.com) 的入站电子邮件 Webhook 请求，验证签名以防止滥用，并将邮件内容转发到指定的邮箱。

**支持平台：**
- ✅ **Vercel** (Edge Functions / Serverless)
- ✅ **Cloudflare** (Pages / Workers)
- ✅ **Tencent EdgeOne** (Pages / Edge Functions)

---

## ✨ 功能特性

*   **🛡️ 企业级安全验证**：内置 Resend Webhook 签名验证机制 (`svix-signature` check)。通过 HMAC-SHA256 加密算法校验请求来源，**彻底防止伪造请求和恶意滥用**。
*   **⚡ 零依赖 (Zero-Dependency)**：使用原生 Web Crypto API 编写，无需庞大的 `node_modules`，适配所有 Edge Runtime。
*   **🚀 多端适配**：同一套逻辑完美适配 Vercel、Cloudflare 和腾讯云 EdgeOne。
*   **✉️ 自动转发**：解析 Webhook JSON 数据并自动重组邮件发送。

---

## 🛠️ 准备工作

在部署之前，你需要准备以下信息：

1.  **Resend API Key**: 在 [Resend Dashboard](https://resend.com/api-keys) 生成。
2.  **Webhook Signing Secret**:
    *   进入 [Resend Webhooks](https://resend.com/webhooks)。
    *   创建一个新的 Webhook，URL 填入你部署后的域名（例如 `https://your-app.vercel.app/api/webhook`）。
    *   获取 `Signing Secret` (以 `whsec_` 开头)。
3.  **发送与接收邮箱**:
    *   `FROM_EMAIL`: 必须是在 Resend 中验证过的发件域名（如 `notification@yourdomain.com`）。
    *   `FORWARD_TO_EMAIL`: 你希望接收转发邮件的目标邮箱。

---

## 🚀 部署指南

### 1. Vercel (推荐)

点击上方的 "Deploy with Vercel" 按钮，或者手动操作：

1. Fork 本仓库。
2. 在 Vercel 中导入项目。
3. 框架预设选择 **Other** (或 Next.js 均可，核心在 `/api` 目录)。
4. 在 **Environment Variables** 中填入下方的环境变量。
5. 部署成功后，Webhook 地址为：`https://你的项目名.vercel.app/api/webhook`。

### 2. Cloudflare Pages / Workers

1. Fork 本仓库。
2. 登录 Cloudflare Dashboard，进入 **Workers & Pages** -> **Create Application** -> **Connect to Git**。
3. 选择本仓库。
4. **Build settings**:
    *   Framework preset: **None**
    *   Build command: `(空)`
    *   Build output directory: `public`
5. **Environment variables**: 填入下方的环境变量。
6. 部署成功后，Webhook 地址为：`https://你的项目名.pages.dev/webhook` (Cloudflare 会自动映射 `functions` 目录)。

### 3. Tencent EdgeOne (腾讯云边缘安全加速)

腾讯云 EdgeOne Pages 支持类似 Cloudflare 的函数架构：

1. 登录腾讯云 EdgeOne 控制台，进入 **Pages (边缘页面)**。
2. 点击 **新建项目**，关联你的 GitHub 仓库。
3. **构建配置**:
    *   构建命令: `(留空)`
    *   输出目录: `public`
4. **部署完成后**，进入该项目的 **设置 (Settings)** -> **环境变量 (Environment Variables)**，添加下方的变量。
5. **边缘函数配置** (重要):
    *   确保你的 EdgeOne 套餐支持边缘函数。
    *   本项目代码已适配 EdgeOne 规范，位于 `/edgeone/worker.js` (或者根据 Pages Functions 规范自动识别 `/functions`)。
    *   如果使用纯边缘函数模式，请手动将 `edgeone/worker.js` 的内容复制到 EdgeOne 函数编辑器中。

---

## 🔑 环境变量配置

无论使用哪个平台，必须设置以下环境变量才能正常工作：

| 变量名 | 描述 | 示例 |
| :--- | :--- | :--- |
| `RESEND_API_KEY` | 你的 Resend API 密钥 | `re_123456...` |
| `WEBHOOK_SIGNING_SECRET` | Resend Webhook 签名密钥 (用于加密验证) | `whsec_abc123...` |
| `FROM_EMAIL` | 转发邮件的发件人地址 | `alert@example.com` |
| `FORWARD_TO_EMAIL` | 接收转发邮件的目标地址 | `me@gmail.com` |

---

## 🔒 安全性说明

本项目严格遵循 [Resend Webhook Security](https://resend.com/docs/dashboard/webhooks/verify-webhooks-requests) 规范。

*   **签名验证**: 系统会提取请求头中的 `svix-id`, `svix-timestamp`, 和 `svix-signature`。
*   **时间戳检查**: 拒绝超过 5 分钟的旧请求，防止重放攻击 (Replay Attacks)。
*   **HMAC 计算**: 使用你的 `WEBHOOK_SIGNING_SECRET` 对请求体进行 SHA-256 计算，确保内容未被篡改。

只有验证通过的请求才会触发邮件发送逻辑，确保你的 API 配额不会被恶意扫描消耗。

---

## 📂 项目结构

```text
.
├── api/
│   └── webhook.js       # Vercel Serverless Function 入口
├── functions/
│   └── webhook.js       # Cloudflare Pages Function 入口
├── edgeone/
│   └── worker.js        # Tencent EdgeOne 专用 Worker 逻辑
├── src/
│   └── utils.js         # 共享的加密验证与邮件发送逻辑
├── public/
│   └── index.html       # 默认首页
└── README.md
```

## License

MIT License © 2025
