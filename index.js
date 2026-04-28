import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import pg from 'pg';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}

const { Pool } = pg;

const pool = new Pool({
  connectionString: DATABASE_URL
});
if (!BOT_TOKEN) {
  throw new Error('BOT_TOKEN is required in .env');
}

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  console.log(
    new Date().toISOString(),
    req.method,
    req.path
  );
  next();
});

// =========================================================
// БЛОК 1. TELEGRAM AUTH
// Проверяем, что initData действительно пришел от Telegram
// =========================================================
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

// =========================================================
// БЛОК 2. МАТЕМАТИКА МАРШРУТА
// Сервер сам считает дистанцию
// =========================================================
function haversineMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (deg) => deg * Math.PI / 180;

  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) ** 2;

  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function totalDistanceMeters(points) {
  let dist = 0;

  for (let i = 1; i < points.length; i++) {
    dist += haversineMeters(
      points[i - 1].lat,
      points[i - 1].lon,
      points[i].lat,
      points[i].lon
    );
  }

  return dist;
}

// =========================================================
// БЛОК 3. ГЕОМЕТРИЯ СЕТКИ
// Сервер сам переводит GPS-точки в клетки
// =========================================================
function gridGeometry(center, size, gridSizeMeters) {
  const metersPerDegLat = 111320;
  const metersPerDegLon = 111320 * Math.cos(center.lat * Math.PI / 180);

  const half = gridSizeMeters / 2;
  const topLat = center.lat + (half / metersPerDegLat);
  const bottomLat = center.lat - (half / metersPerDegLat);
  const leftLon = center.lon - (half / metersPerDegLon);
  const rightLon = center.lon + (half / metersPerDegLon);

  const cellHeightDeg = (topLat - bottomLat) / size;
  const cellWidthDeg = (rightLon - leftLon) / size;

  return {
    topLat,
    bottomLat,
    leftLon,
    rightLon,
    cellHeightDeg,
    cellWidthDeg
  };
}

function pointToCellIndex(point, center, size, gridSizeMeters) {
  const g = gridGeometry(center, size, gridSizeMeters);

  if (
    point.lat > g.topLat ||
    point.lat < g.bottomLat ||
    point.lon < g.leftLon ||
    point.lon > g.rightLon
  ) {
    return null;
  }

  const row = Math.min(
    size - 1,
    Math.max(0, Math.floor((g.topLat - point.lat) / g.cellHeightDeg))
  );

  const col = Math.min(
    size - 1,
    Math.max(0, Math.floor((point.lon - g.leftLon) / g.cellWidthDeg))
  );

  return row * size + col;
}

function uniqueOrderedCellRoute(points, center, size, gridSizeMeters) {
  const route = [];
  const seen = new Set();

  points.forEach((point) => {
    const cellIndex = pointToCellIndex(point, center, size, gridSizeMeters);
    if (cellIndex === null) return;
    if (seen.has(cellIndex)) return;

    seen.add(cellIndex);
    route.push(cellIndex);
  });

  return route;
}

// =========================================================
// БЛОК 4. ВСПОМОГАТЕЛЬНАЯ ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ
// =========================================================
function normalizePoints(points) {
  if (!Array.isArray(points)) return [];

  return points
    .map((p) => ({
      lat: Number(p.lat),
      lon: Number(p.lon),
      ts: p.ts ? Number(p.ts) : null
    }))
    .filter((p) =>
      Number.isFinite(p.lat) &&
      Number.isFinite(p.lon)
    );
}

// =========================================================
// БЛОК 5. HEALTHCHECK
// =========================================================
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'eto-moe-auth' });
});

// =========================================================
// БЛОК 6. STAGE 3.1 AUTH
// =========================================================
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

// =========================================================
// БЛОК 7. STAGE 3.2A FINISH RUN
// Сервер принимает маршрут и считает summary
// =========================================================
app.post('/api/runs/finish', (req, res) => {
  const { initData, routeCenter, grid, points } = req.body || {};

  // 1. Проверяем Telegram-пользователя
  const auth = validateTelegramInitData(initData, BOT_TOKEN);
  if (!auth.ok) {
    return res.status(401).json(auth);
  }

  // 2. Проверяем центр карты
  const center = {
    lat: Number(routeCenter?.lat),
    lon: Number(routeCenter?.lon)
  };

  if (!Number.isFinite(center.lat) || !Number.isFinite(center.lon)) {
    return res.status(400).json({
      ok: false,
      error: 'routeCenter is invalid'
    });
  }

  // 3. Проверяем настройки сетки
  const size = Number(grid?.size);
  const gridSizeMeters = Number(grid?.gridSizeMeters);

  if (!Number.isFinite(size) || size <= 0) {
    return res.status(400).json({
      ok: false,
      error: 'grid.size is invalid'
    });
  }

  if (!Number.isFinite(gridSizeMeters) || gridSizeMeters <= 0) {
    return res.status(400).json({
      ok: false,
      error: 'grid.gridSizeMeters is invalid'
    });
  }

  // 4. Нормализуем точки
  const safePoints = normalizePoints(points);

  if (safePoints.length === 0) {
    return res.status(400).json({
      ok: false,
      error: 'points are missing or invalid'
    });
  }

  // 5. Считаем дистанцию
  const distanceMeters = totalDistanceMeters(safePoints);

  // 6. Считаем клетки маршрута
  const route = uniqueOrderedCellRoute(
    safePoints,
    center,
    size,
    gridSizeMeters
  );

  // 7. Пока без базы:
  // считаем, что каждая клетка маршрута = "новая"
  const routeCells = route.length;
  const captured = route.length;
  const alreadyMine = 0;
  const fromFree = route.length;
  const fromEnemy1 = 0;
  const fromEnemy2 = 0;

  const user = auth.user || {};

  return res.json({
    ok: true,
    user: {
      telegramId: user.id ?? null,
      firstName: user.first_name ?? null,
      username: user.username ?? null
    },
    summary: {
      pointsCount: safePoints.length,
      routeCells,
      captured,
      fromFree,
      fromEnemy1,
      fromEnemy2,
      alreadyMine,
      distanceMeters: Math.round(distanceMeters)
    },
    route
  });
});

// =========================================================
// БЛОК 8. СТАРТ СЕРВЕРА
// =========================================================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
