/**
 * Tencent EdgeOne Worker for Resend Webhook
 * 部署位置: 边缘函数 (Edge Functions)
 */

// 监听 Fetch 事件
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  // 1. 方法限制
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 2. 获取环境变量
  // 注意：在 EdgeOne 控制台设置的环境变量会成为全局变量
  // 我们使用 typeof 检查以防止本地测试时报错
  const API_KEY = typeof RESEND_API_KEY !== 'undefined' ? RESEND_API_KEY : null;
  const SECRET = typeof WEBHOOK_SIGNING_SECRET !== 'undefined' ? WEBHOOK_SIGNING_SECRET : null;
  const FWD_TO = typeof FORWARD_TO_EMAIL !== 'undefined' ? FORWARD_TO_EMAIL : null;
  const FWD_FROM = typeof FROM_EMAIL !== 'undefined' ? FROM_EMAIL : null;

  if (!API_KEY || !SECRET || !FWD_TO || !FWD_FROM) {
    return new Response('EdgeOne Config Error: Missing Env Vars', { status: 500 });
  }

  // 3. 提取签名头
  const svixId = request.headers.get('svix-id');
  const svixTimestamp = request.headers.get('svix-timestamp');
  const svixSignature = request.headers.get('svix-signature');

  if (!svixId || !svixTimestamp || !svixSignature) {
    return new Response('Missing Signature Headers', { status: 401 });
  }

  // 4. 获取 Body 文本
  let bodyText;
  try {
    bodyText = await request.text();
  } catch (e) {
    return new Response('Read Body Failed', { status: 400 });
  }

  // 5. 验证签名 (核心安全逻辑)
  try {
    const isValid = await verifyResendSignature(
      bodyText,
      svixId,
      svixTimestamp,
      svixSignature,
      SECRET
    );

    if (!isValid) {
      return new Response('Invalid Signature', { status: 401 });
    }
  } catch (e) {
    return new Response(`Verification Error: ${e.message}`, { status: 500 });
  }

  // 6. 解析与转发
  try {
    const payload = JSON.parse(bodyText);
    const emailData = payload.data || payload;

    // 构造 HTML 内容
    const subject = `[EdgeOne Forward] ${emailData.subject || 'No Subject'}`;
    const htmlContent = `
      <div style="font-family: system-ui, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
        <h2 style="color: #0052d9;">📨 Email via EdgeOne</h2>
        <p><strong>From:</strong> ${emailData.from}</p>
        <p><strong>To:</strong> ${emailData.to && emailData.to.join(', ')}</p>
        <p><strong>Subject:</strong> ${emailData.subject}</p>
        <hr />
        <div>${emailData.html || emailData.text || '(No content)'}</div>
      </div>
    `;

    // 调用 Resend API
    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: FWD_FROM,
        to: FWD_TO,
        subject: subject,
        html: htmlContent,
      }),
    });

    if (!resendRes.ok) {
      const err = await resendRes.text();
      return new Response(`Resend API Error: ${err}`, { status: 502 });
    }

    return new Response(JSON.stringify({ status: 'ok', provider: 'edgeone' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (e) {
    return new Response(`Processing Error: ${e.message}`, { status: 500 });
  }
}

/**
 * --- Web Crypto API 签名验证工具 ---
 * 适用于 EdgeOne 运行时
 */
async function verifyResendSignature(payload, id, timestamp, signatureHeader, secret) {
  // 1. 校验时间戳 (5分钟有效期)
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Math.abs(now - ts) > 300) {
    return false;
  }

  // 2. 构造待签名字符串
  const encoder = new TextEncoder();
  const toSign = `${id}.${timestamp}.${payload}`;

  // 3. 处理 Secret (去前缀 + Base64解码)
  let secretKey = secret;
  if (secretKey.startsWith('whsec_')) {
    secretKey = secretKey.substring(6);
  }
  
  // EdgeOne 支持标准的 atob
  const keyBytes = Uint8Array.from(atob(secretKey), c => c.charCodeAt(0));

  // 4. 导入 HMAC Key
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

  // 6. Base64 编码
  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));

  // 7. 匹配签名
  const expectedSignature = `v1,${signatureBase64}`;
  const signatures = signatureHeader.split(' ');

  return signatures
