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

if (!BOT_TOKEN) {
  throw new Error('BOT_TOKEN is required in .env');
}

const { Pool } = pg;

const pool = new Pool({
  connectionString: DATABASE_URL
});

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
// БЛОК 4. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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

function makeCellKey(center, size, gridSizeMeters, cellIndex) {
  return [
    center.lat.toFixed(6),
    center.lon.toFixed(6),
    size,
    gridSizeMeters,
    cellIndex
  ].join(':');
}

async function findOrCreateUser(client, telegramUser) {
  const telegramId = telegramUser?.id;

  if (!telegramId) {
    throw new Error('telegram user id is missing');
  }

  const existing = await client.query(
    `
      select id, telegram_id, username, first_name, last_name
      from users
      where telegram_id = $1
      limit 1
    `,
    [telegramId]
  );

  if (existing.rows.length > 0) {
    const row = existing.rows[0];

    await client.query(
      `
        update users
        set
          username = $2,
          first_name = $3,
          last_name = $4
        where id = $1
      `,
      [
        row.id,
        telegramUser.username ?? null,
        telegramUser.first_name ?? null,
        telegramUser.last_name ?? null
      ]
    );

    return row.id;
  }

  const inserted = await client.query(
    `
      insert into users (telegram_id, username, first_name, last_name)
      values ($1, $2, $3, $4)
      returning id
    `,
    [
      telegramId,
      telegramUser.username ?? null,
      telegramUser.first_name ?? null,
      telegramUser.last_name ?? null
    ]
  );

  return inserted.rows[0].id;
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
// БЛОК 7. STAGE 3.3D FINISH RUN + DB
// =========================================================
app.post('/api/runs/finish', async (req, res) => {
  const client = await pool.connect();

  try {
    const { initData, routeCenter, grid, points, durationSeconds } = req.body || {};

    const auth = validateTelegramInitData(initData, BOT_TOKEN);
    if (!auth.ok) {
      return res.status(401).json(auth);
    }

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

    const safePoints = normalizePoints(points);

    if (safePoints.length === 0) {
      return res.status(400).json({
        ok: false,
        error: 'points are missing or invalid'
      });
    }

    const distanceMeters = Math.round(totalDistanceMeters(safePoints));
    const route = uniqueOrderedCellRoute(
      safePoints,
      center,
      size,
      gridSizeMeters
    );

    const runDurationSeconds = Number.isFinite(Number(durationSeconds))
      ? Number(durationSeconds)
      : 0;

    await client.query('begin');

    const userId = await findOrCreateUser(client, auth.user);

    let fromFree = 0;
    let fromEnemy1 = 0;
    let fromEnemy2 = 0;
    let alreadyMine = 0;
    let captured = 0;

    for (const cellIndex of route) {
      const cellKey = makeCellKey(center, size, gridSizeMeters, cellIndex);

      const existingOwner = await client.query(
        `
          select owner_user_id
          from cell_ownership
          where cell_key = $1
          limit 1
        `,
        [cellKey]
      );

      if (existingOwner.rows.length === 0) {
        fromFree += 1;
        captured += 1;

        await client.query(
          `
            insert into cell_ownership (cell_key, owner_user_id, updated_at)
            values ($1, $2, now())
          `,
          [cellKey, userId]
        );
      } else {
        const ownerUserId = existingOwner.rows[0].owner_user_id;

        if (Number(ownerUserId) === Number(userId)) {
          alreadyMine += 1;
        } else {
          captured += 1;
          fromEnemy1 += 1;

          await client.query(
            `
              update cell_ownership
              set owner_user_id = $2,
                  updated_at = now()
              where cell_key = $1
            `,
            [cellKey, userId]
          );
        }
      }
    }

    const insertedRun = await client.query(
      `
        insert into runs (
          user_id,
          distance_meters,
          points_count,
          route_cells_count,
          captured_count,
          duration_seconds,
          started_at,
          finished_at
        )
        values ($1, $2, $3, $4, $5, $6, null, now())
        returning id
      `,
      [
        userId,
        distanceMeters,
        safePoints.length,
        route.length,
        captured,
        runDurationSeconds
      ]
    );

    await client.query('commit');

    return res.json({
      ok: true,
      runId: insertedRun.rows[0].id,
      user: {
        telegramId: auth.user?.id ?? null,
        firstName: auth.user?.first_name ?? null,
        username: auth.user?.username ?? null
      },
      summary: {
        pointsCount: safePoints.length,
        routeCells: route.length,
        captured,
        fromFree,
        fromEnemy1,
        fromEnemy2,
        alreadyMine,
        distanceMeters,
        durationSeconds: runDurationSeconds
      },
      route
    });
  } catch (error) {
    await client.query('rollback');
    console.error('finish-run db error:', error);

    return res.status(500).json({
      ok: false,
      error: error.message
    });
  } finally {
    client.release();
  }
});

// =========================================================
// БЛОК 8. STAGE 3.3E MAP STATE
// =========================================================
app.get('/api/map/state', async (req, res) => {
  try {
    const center = {
      lat: Number(req.query.lat),
      lon: Number(req.query.lon)
    };

    const size = Number(req.query.size);
    const gridSizeMeters = Number(req.query.gridSizeMeters);

    if (!Number.isFinite(center.lat) || !Number.isFinite(center.lon)) {
      return res.status(400).json({
        ok: false,
        error: 'lat/lon are invalid'
      });
    }

    if (!Number.isFinite(size) || size <= 0) {
      return res.status(400).json({
        ok: false,
        error: 'size is invalid'
      });
    }

    if (!Number.isFinite(gridSizeMeters) || gridSizeMeters <= 0) {
      return res.status(400).json({
        ok: false,
        error: 'gridSizeMeters is invalid'
      });
    }

    const cellKeys = [];
    const keyToIndex = new Map();

    for (let cellIndex = 0; cellIndex < size * size; cellIndex++) {
      const cellKey = makeCellKey(center, size, gridSizeMeters, cellIndex);
      cellKeys.push(cellKey);
      keyToIndex.set(cellKey, cellIndex);
    }

    const result = await pool.query(
      `
        select
          co.cell_key,
          co.owner_user_id,
          u.telegram_id
        from cell_ownership co
        left join users u on u.id = co.owner_user_id
        where co.cell_key = any($1::text[])
      `,
      [cellKeys]
    );

    const cells = result.rows
      .map((row) => ({
        cellIndex: keyToIndex.get(row.cell_key),
        ownerTelegramId: row.telegram_id
      }))
      .filter((row) => Number.isInteger(row.cellIndex));

    return res.json({
      ok: true,
      center,
      size,
      gridSizeMeters,
      cells
    });
  } catch (error) {
    console.error('map-state error:', error);

    return res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

// =========================================================
// БЛОК 9. DB CHECK
// =========================================================
app.get('/api/db-check', async (_req, res) => {
  try {
    const result = await pool.query('select now() as now');

    res.json({
      ok: true,
      db: 'connected',
      now: result.rows[0].now
    });
  } catch (error) {
    console.error('db-check error:', error);

    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

// =========================================================
// БЛОК 10. DB INIT
// Временно. Потом лучше удалить.
// =========================================================
app.get('/api/db-init', async (_req, res) => {
  try {
    await pool.query(`
      create table if not exists users (
        id bigserial primary key,
        telegram_id bigint unique not null,
        username text,
        first_name text,
        last_name text,
        created_at timestamptz default now()
      );
    `);

    await pool.query(`
      create table if not exists runs (
        id bigserial primary key,
        user_id bigint not null references users(id),
        distance_meters integer not null default 0,
        points_count integer not null default 0,
        route_cells_count integer not null default 0,
        captured_count integer not null default 0,
        duration_seconds integer not null default 0,
        started_at timestamptz,
        finished_at timestamptz default now(),
        created_at timestamptz default now()
      );
    `);

    await pool.query(`
      create table if not exists cell_ownership (
        cell_key text primary key,
        owner_user_id bigint references users(id),
        updated_at timestamptz default now()
      );
    `);

    res.json({
      ok: true,
      message: 'tables created'
    });
  } catch (error) {
    console.error('db-init error:', error);

    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

// =========================================================
// БЛОК 11. СТАРТ СЕРВЕРА
// =========================================================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
