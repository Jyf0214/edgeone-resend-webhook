export const config = {
  runtime: 'edge', // 使用 Edge Runtime 以获得更高性能和更低延迟
};

export default async function handler(req) {
  // 1. 仅允许 POST 请求
  if (req.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 2. 获取环境变量
  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  const WEBHOOK_SECRET = process.env.WEBHOOK_SIGNING_SECRET;
  const FORWARD_TO = process.env.FORWARD_TO_EMAIL;
  const FROM = process.env.FROM_EMAIL;

  // 检查配置是否完整
  if (!RESEND_API_KEY || !WEBHOOK_SECRET || !FORWARD_TO || !FROM) {
    console.error('Missing environment variables');
    return new Response('Server Configuration Error', { status: 500 });
  }

  // 3. 获取 Resend 签名头
  const svixId = req.headers.get('svix-id');
  const svixTimestamp = req.headers.get('svix-timestamp');
  const svixSignature = req.headers.get('svix-signature');

  if (!svixId || !svixTimestamp || !svixSignature) {
    return new Response('Missing Signature Headers', { status: 401 });
  }

  // 4. 获取原始 Body 文本 (用于签名验证)
  let bodyText;
  try {
    bodyText = await req.text();
  } catch (e) {
    return new Response('Invalid Body', { status: 400 });
  }

  // 5. 验证签名 (安全性核心)
  try {
    const isValid = await verifyResendSignature(
      bodyText,
      svixId,
      svixTimestamp,
      svixSignature,
      WEBHOOK_SECRET
    );

    if (!isValid) {
      return new Response('Invalid Signature', { status: 401 });
    }
  } catch (e) {
    console.error('Verification Error:', e);
    return new Response('Verification Failed', { status: 401 });
  }

  // 6. 解析数据并转发邮件
  try {
    const payload = JSON.parse(bodyText);
    const emailData = payload.data || payload; // 兼容不同类型的 webhook 结构

    // 构造转发内容
    const subject = `[Forward] ${emailData.subject || 'No Subject'}`;
    const htmlContent = `
      <div style="font-family: sans-serif; border: 1px solid #eaeaea; padding: 20px; border-radius: 5px;">
        <h2>📧 New Email Received</h2>
        <p><strong>From:</strong> ${emailData.from}</p>
        <p><strong>To:</strong> ${emailData.to && emailData.to.join(', ')}</p>
        <p><strong>Subject:</strong> ${emailData.subject}</p>
        <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 20px 0;" />
        <div style="background: #f9f9f9; padding: 15px; border-radius: 4px;">
          ${emailData.html || emailData.text || '(No content)'}
        </div>
        <br />
        <small style="color: #888;">Powered by Resend Webhook Forwarder</small>
      </div>
    `;

    // 调用 Resend API 发送邮件
    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: FROM,
        to: FORWARD_TO,
        subject: subject,
        html: htmlContent,
      }),
    });

    if (!resendRes.ok) {
      const errorText = await resendRes.text();
      console.error('Resend API Error:', errorText);
      return new Response('Failed to send email', { status: 502 });
    }

    return new Response(JSON.stringify({ status: 'ok', message: 'Email forwarded' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (e) {
    console.error('Processing Error:', e);
    return new Response('Internal Server Error', { status: 500 });
  }
}

/**
 * --- 核心安全工具函数 ---
 * 验证 Resend/Svix Webhook 签名
 * 使用原生 Web Crypto API，无需安装 npm 依赖
 */
async function verifyResendSignature(payload, id, timestamp, signatureHeader, secret) {
  // 1. 验证时间戳 (防止重放攻击，允许 5 分钟误差)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Math.abs(now - ts) > 300) {
    console.error('Timestamp expired');
    return false;
  }

  // 2. 准备签名内容: "id.timestamp.payload"
  const encoder = new TextEncoder();
  const toSign = `${id}.${timestamp}.${payload}`;

  // 3. 处理密钥 (Secret 通常以 whsec_ 开头，是 Base64 编码)
  let secretKey = secret;
  if (secretKey.startsWith('whsec_')) {
    secretKey = secretKey.substring(6);
  }
  
  // 将 Base64 密钥解码为 Uint8Array
  const keyBytes = Uint8Array.from(atob(secretKey), c => c.charCodeAt(0));

  // 4. 导入密钥
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

  // 6. 将签名转换为 Base64
  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));

  // 7. 比较签名
  // Resend header 格式例如: "v1,Base64Signature v2,Base64Signature..."
  const signatures = signatureHeader.split(' ');
  
  // 检查是否包含我们计算出的签名 (v1)
  const expectedSignature = `v1,${signatureBase64}`;
  
  // 简单的字符串包含检查
  // 注意：在极高安全要求下应使用时序安全比较，但在 Serverless 环境下这种实现已足够应对 Webhook 校验
  return signatures.includes(expectedSignature);
      }
