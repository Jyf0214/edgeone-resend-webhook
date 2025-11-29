/**
 * Cloudflare Pages Function for Resend Webhook
 * 路由地址: /webhook
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. 获取环境变量 (Cloudflare Pages 中从 context.env 获取)
  const RESEND_API_KEY = env.RESEND_API_KEY;
  const WEBHOOK_SECRET = env.WEBHOOK_SIGNING_SECRET;
  const FORWARD_TO = env.FORWARD_TO_EMAIL;
  const FROM = env.FROM_EMAIL;

  if (!RESEND_API_KEY || !WEBHOOK_SECRET || !FORWARD_TO || !FROM) {
    return new Response('Server Configuration Error: Missing Env Vars', { status: 500 });
  }

  // 2. 获取 Resend 签名头
  const svixId = request.headers.get('svix-id');
  const svixTimestamp = request.headers.get('svix-timestamp');
  const svixSignature = request.headers.get('svix-signature');

  if (!svixId || !svixTimestamp || !svixSignature) {
    return new Response('Missing Signature Headers', { status: 401 });
  }

  // 3. 获取 Body 文本
  let bodyText;
  try {
    bodyText = await request.text();
  } catch (e) {
    return new Response('Invalid Request Body', { status: 400 });
  }

  // 4. 执行签名验证 (Zero-dependency)
  try {
    const isValid = await verifyResendSignature(
      bodyText,
      svixId,
      svixTimestamp,
      svixSignature,
      WEBHOOK_SECRET
    );

    if (!isValid) {
      console.log('Signature verification failed');
      return new Response('Invalid Signature', { status: 401 });
    }
  } catch (e) {
    console.error('Crypto Error:', e);
    return new Response('Verification Error', { status: 500 });
  }

  // 5. 解析并转发邮件
  try {
    const payload = JSON.parse(bodyText);
    const emailData = payload.data || payload;

    // 构造邮件内容
    const subject = `[Forward] ${emailData.subject || 'No Subject'}`;
    const htmlContent = `
      <div style="font-family: sans-serif; border: 1px solid #eaeaea; padding: 20px; border-radius: 5px;">
        <h2>📧 Email Forwarded via Cloudflare</h2>
        <p><strong>From:</strong> ${emailData.from}</p>
        <p><strong>To:</strong> ${emailData.to && emailData.to.join(', ')}</p>
        <p><strong>Subject:</strong> ${emailData.subject}</p>
        <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 20px 0;" />
        <div style="background: #f9f9f9; padding: 15px; border-radius: 4px;">
          ${emailData.html || emailData.text || '(No content)'}
        </div>
      </div>
    `;

    // 发送请求给 Resend
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
      return new Response('Failed to forward email', { status: 502 });
    }

    return new Response(JSON.stringify({ status: 'ok', provider: 'cloudflare' }), {
      headers: { 'Content-Type': 'application/json' },
      status: 200
    });

  } catch (err) {
    console.error('Processing Error:', err);
    return new Response('Internal Server Error', { status: 500 });
  }
}

/**
 * --- 工具函数: Web Crypto API 签名验证 ---
 * 兼容 Cloudflare Workers Runtime
 */
async function verifyResendSignature(payload, id, timestamp, signatureHeader, secret) {
  // 1. 验证时间戳 (5分钟窗口)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Math.abs(now - ts) > 300) {
    return false;
  }

  // 2. 构造签名字符串
  const encoder = new TextEncoder();
  const toSign = `${id}.${timestamp}.${payload}`;

  // 3. 处理 Secret (移除 whsec_ 前缀并 Base64 解码)
  let secretKey = secret;
  if (secretKey.startsWith('whsec_')) {
    secretKey = secretKey.substring(6);
  }
  
  // Cloudflare Worker 支持标准的 atob
  const keyBytes = Uint8Array.from(atob(secretKey), c => c.charCodeAt(0));

  // 4. 导入 Key
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // 5. 计算签名
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(toSign)
  );

  // 6. 转 Base64
  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));

  // 7. 对比
  const expectedSignature = `v1,${signatureBase64}`;
  const signatures = signatureHeader.split(' ');

  return signatures.includes(expectedSignature);
}
