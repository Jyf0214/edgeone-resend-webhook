/**
 * --- 核心工具函数模块 ---
 * 本文件包含项目的核心逻辑：
 * 1. Webhook 签名验证
 * 2. 邮件转发
 *
 * 在实际部署中，为简化操作，这些函数已被内联到每个平台的入口文件中。
 */

/**
 * 验证 Resend/Svix Webhook 签名 (使用 Web Crypto API)。
 * @param {string} payload - 原始请求体文本。
 * @param {string} id - `svix-id` 请求头。
 * @param {string} timestamp - `svix-timestamp` 请求头。
 * @param {string} signatureHeader - `svix-signature` 请求头。
 * @param {string} secret - 你的 Webhook Signing Secret。
 * @returns {Promise<boolean>} - 如果签名有效则返回 true，否则返回 false。
 */
export async function verifyResendSignature(payload, id, timestamp, signatureHeader, secret) {
  // 1. 验证时间戳，防止重放攻击 (5 分钟窗口)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Math.abs(now - ts) > 300) {
    console.error("Timestamp validation failed.");
    return false;
  }

  // 2. 构造待签名的内容
  const encoder = new TextEncoder();
  const toSign = `${id}.${timestamp}.${payload}`;

  // 3. 处理密钥 (Secret 是 Base64 编码的，且有 'whsec_' 前缀)
  let secretKey = secret;
  if (secretKey.startsWith('whsec_')) {
    secretKey = secretKey.substring(6);
  }
  
  // Base64 解码
  const keyBytes = Uint8Array.from(atob(secretKey), c => c.charCodeAt(0));

  // 4. 导入 HMAC 密钥
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // 5. 计算 HMAC-SHA256 签名
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(toSign)
  );

  // 6. 将签名结果转换为 Base64
  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));

  // 7. 与请求头中的签名进行比较
  // 签名头格式为 "v1,Base64Signature v2,AnotherSignature..."
  const expectedSignature = `v1,${signatureBase64}`;
  const providedSignatures = signatureHeader.split(' ');

  // 使用 includes 方法进行安全检查
  return providedSignatures.includes(expectedSignature);
}

/**
 * 调用 Resend API 转发邮件。
 * @param {object} params - 邮件参数。
 * @param {string} params.apiKey - Resend API Key。
 * @param {string} params.from - 发件人邮箱。
 * @param {string} params.to - 收件人邮箱。
 * @param {string} params.subject - 邮件主题。
 * @param {string} params.html - 邮件 HTML 内容。
 * @returns {Promise<Response>} - fetch API 的响应对象。
 */
export async function forwardEmail({ apiKey, from, to, subject, html }) {
  return fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to,
      subject,
      html,
    }),
  });
    }
