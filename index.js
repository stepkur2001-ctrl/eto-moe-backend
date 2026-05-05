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
  throw new Error('BOT_TOKEN is required');
}

const { Pool } = pg;

const pool = new Pool({
  connectionString: DATABASE_URL
});

app.use(cors());
app.use(express.json({ limit: '5mb' }));

app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.path);
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
// БЛОК 2. ОБЩАЯ МАТЕМАТИКА
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
      Number.isFinite(p.lon) &&
      p.lat >= -85 &&
      p.lat <= 85 &&
      p.lon >= -180 &&
      p.lon <= 180
    );
}

// =========================================================
// БЛОК 3. ГЛОБАЛЬНАЯ СЕТКА ЧЕРЕЗ WEB MERCATOR
// =========================================================
const EARTH_RADIUS = 6378137;
const DEFAULT_CELL_SIZE_METERS = 500;

function lonToMercatorX(lon) {
  return EARTH_RADIUS * (lon * Math.PI / 180);
}

function latToMercatorY(lat) {
  const clamped = Math.max(-85.05112878, Math.min(85.05112878, lat));
  const rad = clamped * Math.PI / 180;
  return EARTH_RADIUS * Math.log(Math.tan(Math.PI / 4 + rad / 2));
}

function pointToGlobalCell(point, cellSizeMeters) {
  const x = lonToMercatorX(point.lon);
  const y = latToMercatorY(point.lat);

  return {
    gridX: Math.floor(x / cellSizeMeters),
    gridY: Math.floor(y / cellSizeMeters)
  };
}

function uniqueOrderedGlobalRoute(points, cellSizeMeters) {
  const route = [];
  const seen = new Set();

  for (const point of points) {
    const cell = pointToGlobalCell(point, cellSizeMeters);
    const key = `${cell.gridX}:${cell.gridY}`;

    if (seen.has(key)) continue;
    seen.add(key);
    route.push(cell);
  }

  return route;
}

function boundsToGridRange(minLat, maxLat, minLon, maxLon, cellSizeMeters) {
  const minX = Math.floor(lonToMercatorX(minLon) / cellSizeMeters);
  const maxX = Math.floor(lonToMercatorX(maxLon) / cellSizeMeters);
  const minY = Math.floor(latToMercatorY(minLat) / cellSizeMeters);
  const maxY = Math.floor(latToMercatorY(maxLat) / cellSizeMeters);

  return {
    minGridX: Math.min(minX, maxX),
    maxGridX: Math.max(minX, maxX),
    minGridY: Math.min(minY, maxY),
    maxGridY: Math.max(minY, maxY)
  };
}

// =========================================================
// БЛОК 4. USERS
// =========================================================
async function findOrCreateUser(client, telegramUser) {
  const telegramId = telegramUser?.id;

  if (!telegramId) {
    throw new Error('telegram user id is missing');
  }

  const existing = await client.query(
    `
      select id
      from users
      where telegram_id = $1
      limit 1
    `,
    [telegramId]
  );

  if (existing.rows.length > 0) {
    const userId = existing.rows[0].id;

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
        userId,
        telegramUser.username ?? null,
        telegramUser.first_name ?? null,
        telegramUser.last_name ?? null
      ]
    );

    return userId;
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
// БЛОК 5. BASIC ENDPOINTS
// =========================================================
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'eto-moe-auth-global' });
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
// БЛОК 6. GLOBAL DB INIT
// Один раз вызвать в браузере
// =========================================================
app.get('/api/db-init-global', async (_req, res) => {
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
      create table if not exists global_cell_ownership (
        grid_x bigint not null,
        grid_y bigint not null,
        owner_user_id bigint references users(id),
        updated_at timestamptz default now(),
        primary key (grid_x, grid_y)
      );
    `);

    await pool.query(`
      create index if not exists idx_global_cell_ownership_owner
      on global_cell_ownership(owner_user_id);
    `);

    res.json({
      ok: true,
      message: 'global tables created'
    });
  } catch (error) {
    console.error('db-init-global error:', error);
    res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

// =========================================================
// БЛОК 7. GLOBAL FINISH RUN
// =========================================================
app.post('/api/runs/finish-global', async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      initData,
      points,
      durationSeconds,
      cellSizeMeters
    } = req.body || {};

    const auth = validateTelegramInitData(initData, BOT_TOKEN);
    if (!auth.ok) {
      return res.status(401).json(auth);
    }

    const safePoints = normalizePoints(points);
    if (safePoints.length === 0) {
      return res.status(400).json({
        ok: false,
        error: 'points are missing or invalid'
      });
    }

    const safeCellSize = Number.isFinite(Number(cellSizeMeters)) && Number(cellSizeMeters) > 0
      ? Number(cellSizeMeters)
      : DEFAULT_CELL_SIZE_METERS;

    const route = uniqueOrderedGlobalRoute(safePoints, safeCellSize);
    const distanceMeters = Math.round(totalDistanceMeters(safePoints));
    const runDurationSeconds = Number.isFinite(Number(durationSeconds))
      ? Number(durationSeconds)
      : 0;

    await client.query('begin');

    const userId = await findOrCreateUser(client, auth.user);

    let fromFree = 0;
    let fromEnemy = 0;
    let alreadyMine = 0;
    let captured = 0;

    for (const cell of route) {
      const existingOwner = await client.query(
        `
          select owner_user_id
          from global_cell_ownership
          where grid_x = $1 and grid_y = $2
          limit 1
        `,
        [cell.gridX, cell.gridY]
      );

      if (existingOwner.rows.length === 0) {
        fromFree += 1;
        captured += 1;

        await client.query(
          `
            insert into global_cell_ownership (grid_x, grid_y, owner_user_id, updated_at)
            values ($1, $2, $3, now())
          `,
          [cell.gridX, cell.gridY, userId]
        );
      } else {
        const ownerUserId = existingOwner.rows[0].owner_user_id;

        if (Number(ownerUserId) === Number(userId)) {
          alreadyMine += 1;
        } else {
          fromEnemy += 1;
          captured += 1;

          await client.query(
            `
              update global_cell_ownership
              set owner_user_id = $3,
                  updated_at = now()
              where grid_x = $1 and grid_y = $2
            `,
            [cell.gridX, cell.gridY, userId]
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
      summary: {
        pointsCount: safePoints.length,
        routeCells: route.length,
        captured,
        fromFree,
        fromEnemy,
        alreadyMine,
        distanceMeters,
        durationSeconds: runDurationSeconds,
        cellSizeMeters: safeCellSize
      },
      route
    });
  } catch (error) {
    await client.query('rollback');
    console.error('finish-global error:', error);

    return res.status(500).json({
      ok: false,
      error: error.message
    });
  } finally {
    client.release();
  }
});

// =========================================================
// БЛОК 8. VIEWPORT MAP
// =========================================================
app.get('/api/map/viewport', async (req, res) => {
  try {
    const minLat = Number(req.query.minLat);
    const maxLat = Number(req.query.maxLat);
    const minLon = Number(req.query.minLon);
    const maxLon = Number(req.query.maxLon);

    const safeCellSize = Number.isFinite(Number(req.query.cellSizeMeters)) && Number(req.query.cellSizeMeters) > 0
      ? Number(req.query.cellSizeMeters)
      : DEFAULT_CELL_SIZE_METERS;

    if (
      !Number.isFinite(minLat) ||
      !Number.isFinite(maxLat) ||
      !Number.isFinite(minLon) ||
      !Number.isFinite(maxLon)
    ) {
      return res.status(400).json({
        ok: false,
        error: 'viewport bounds are invalid'
      });
    }

    const range = boundsToGridRange(
      minLat,
      maxLat,
      minLon,
      maxLon,
      safeCellSize
    );

    const result = await pool.query(
      `
        select
          gco.grid_x,
          gco.grid_y,
          gco.owner_user_id,
          u.telegram_id
          u.username
        from global_cell_ownership gco
        left join users u on u.id = gco.owner_user_id
        where gco.grid_x between $1 and $2
          and gco.grid_y between $3 and $4
      `,
      [range.minGridX, range.maxGridX, range.minGridY, range.maxGridY]
    );

    return res.json({
      ok: true,
      cellSizeMeters: safeCellSize,
      bounds: {
        minLat,
        maxLat,
        minLon,
        maxLon
      },
      cells: result.rows.map((row) => ({
        gridX: Number(row.grid_x),
        gridY: Number(row.grid_y),
        ownerTelegramId: row.telegram_id != null ? Number(row.telegram_id) : null
        ownerUsername: row.username ?? null
      }))
    });
  } catch (error) {
    console.error('viewport map error:', error);
    return res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

// =========================================================
// БЛОК 9. СТАРТ СЕРВЕРА
// =========================================================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
