import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;

if (!BOT_TOKEN) {
  throw new Error('BOT_TOKEN is required in .env');
}

app.use(cors());
app.use(express.json({ limit: '1mb' }));

function buildDataCheckString(params) {
  return [...params.entries()]
    .filter(([key]) => key !== 'hash')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
}

function validateTelegramInitData(initData, botToken, maxAgeSeconds = 3600) {
  if (!initData || typeof initData !== 'string') {
    return { ok: false, error: 'initData is missing' };
  }

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');

  if (!hash) {
    return { ok: false, error: 'hash is missing' };
  }

  const authDateRaw = params.get('auth_date');
  const authDate = authDateRaw ? Number(authDateRaw) : NaN;

  if (!Number.isFinite(authDate)) {
    return { ok: false, error: 'auth_date is invalid' };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (nowSeconds - authDate > maxAgeSeconds) {
    return { ok: false, error: 'initData is too old' };
  }

  const dataCheckString = buildDataCheckString(params);

  const secretKey = crypto
    .createHmac('sha256', 'WebAppData')
    .update(botToken)
    .digest();

  const calculatedHash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheckString)
    .digest('hex');

  const hashBuffer = Buffer.from(hash, 'hex');
  const calculatedHashBuffer = Buffer.from(calculatedHash, 'hex');

  if (
    hashBuffer.length !== calculatedHashBuffer.length ||
    !crypto.timingSafeEqual(hashBuffer, calculatedHashBuffer)
  ) {
    return { ok: false, error: 'hash verification failed' };
  }

  const userRaw = params.get('user');
  let user = null;

  try {
    user = userRaw ? JSON.parse(userRaw) : null;
  } catch {
    return { ok: false, error: 'user payload is invalid JSON' };
  }

  return {
    ok: true,
    user,
    authDate,
    queryId: params.get('query_id') || null
  };
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'eto-moe-auth' });
});

app.post('/api/auth/telegram', (req, res) => {
  const { initData } = req.body || {};

  const result = validateTelegramInitData(initData, BOT_TOKEN);

  if (!result.ok) {
    return res.status(401).json(result);
  }

  const user = result.user || {};

  return res.json({
    ok: true,
    user: {
      telegramId: user.id ?? null,
      firstName: user.first_name ?? null,
      lastName: user.last_name ?? null,
      username: user.username ?? null,
      languageCode: user.language_code ?? null,
      isPremium: user.is_premium ?? false
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});