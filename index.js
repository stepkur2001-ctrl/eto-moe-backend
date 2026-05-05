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
// БЛОК 2. ОБЩАЯ МАТЕМАТИКА + АНТИЧИТ
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

const MAX_SEGMENT_SPEED_MPS = 7; // ~25 км/ч
const MAX_AVG_SPEED_MPS = 5; // ~18 км/ч
const MIN_RUN_DURATION_SECONDS = 120;
const MIN_POINTS_COUNT = 5;
const MAX_TELEPORT_DISTANCE_METERS = 250;

function getSegmentStats(points) {
const segments = [];

for (let i = 1; i < points.length; i++) {
const prev = points[i - 1];
const curr = points[i];

const distanceMeters = haversineMeters(
prev.lat,
prev.lon,
curr.lat,
curr.lon
);

const dtSeconds =
prev.ts != null && curr.ts != null
? (curr.ts - prev.ts) / 1000
: null;

let speedMps = null;

if (dtSeconds != null && dtSeconds > 0) {
speedMps = distanceMeters / dtSeconds;
}

segments.push({
distanceMeters,
dtSeconds,
speedMps
});
}

return segments;
}

function validateRunAsFoot(points, durationSeconds) {
if (!Array.isArray(points) || points.length < MIN_POINTS_COUNT) {
return {
ok: false,
error: 'Слишком мало точек для зачёта пробежки'
};
}

if (!Number.isFinite(durationSeconds) || durationSeconds < MIN_RUN_DURATION_SECONDS) {
return {
ok: false,
error: 'Пробежка слишком короткая для зачёта'
};
}

const totalDistance = totalDistanceMeters(points);
const avgSpeedMps = totalDistance / durationSeconds;

if (avgSpeedMps > MAX_AVG_SPEED_MPS) {
return {
ok: false,
error: 'Забег не засчитан: средняя скорость слишком высокая для бегового режима'
};
}

const segments = getSegmentStats(points);

let tooFastSegments = 0;
let teleportSegments = 0;
let measuredSegments = 0;

for (const segment of segments) {
if (!Number.isFinite(segment.dtSeconds) || segment.dtSeconds <= 0) {
continue;
}

measuredSegments += 1;

if (segment.distanceMeters > MAX_TELEPORT_DISTANCE_METERS && segment.dtSeconds < 10) {
teleportSegments += 1;
}

if (Number.isFinite(segment.speedMps) && segment.speedMps > MAX_SEGMENT_SPEED_MPS) {
tooFastSegments += 1;
}
}

if (teleportSegments > 0) {
return {
ok: false,
error: 'Забег не засчитан: обнаружены слишком резкие скачки координат'
};
}

if (measuredSegments > 0) {
const fastShare = tooFastSegments / measuredSegments;

if (fastShare >= 0.25) {
return {
ok: false,
error: 'Забег не засчитан: движение слишком быстрое для бегового режима'
};
}
}

return {
ok: true,
totalDistance,
avgSpeedMps
};
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

const runDurationSeconds = Number.isFinite(Number(durationSeconds))
? Number(durationSeconds)
: 0;

const footValidation = validateRunAsFoot(safePoints, runDurationSeconds);

if (!footValidation.ok) {
return res.status(400).json({
ok: false,
error: footValidation.error
});
}

const safeCellSize = Number.isFinite(Number(cellSizeMeters)) && Number(cellSizeMeters) > 0
? Number(cellSizeMeters)
: DEFAULT_CELL_SIZE_METERS;

const route = uniqueOrderedGlobalRoute(safePoints, safeCellSize);
const distanceMeters = Math.round(footValidation.totalDistance);

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
u.telegram_id,
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
ownerTelegramId: row.telegram_id != null ? Number(row.telegram_id) : null,
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
// БЛОК 8.1 PLAYER PROFILE
// =========================================================
app.get('/api/player/by-telegram-id/:telegramId', async (req, res) => {
try {
const telegramId = Number(req.params.telegramId);

if (!Number.isFinite(telegramId)) {
return res.status(400).json({
ok: false,
error: 'telegramId is invalid'
});
}

const userResult = await pool.query(
`
select
u.id,
u.telegram_id,
u.username,
u.first_name,
u.last_name
from users u
where u.telegram_id = $1
limit 1
`,
[telegramId]
);

if (userResult.rows.length === 0) {
return res.status(404).json({
ok: false,
error: 'player not found'
});
}

const user = userResult.rows[0];

const statsResult = await pool.query(
`
select
coalesce(sum(r.distance_meters), 0) as total_distance_meters,
coalesce(count(r.id), 0) as total_runs,
coalesce(sum(r.captured_count), 0) as total_captured,
max(r.finished_at) as last_run_at
from runs r
where r.user_id = $1
`,
[user.id]
);

const ownedNowResult = await pool.query(
`
select count(*) as owned_now
from global_cell_ownership
where owner_user_id = $1
`,
[user.id]
);

return res.json({
ok: true,
player: {
telegramId: Number(user.telegram_id),
username: user.username ?? null,
firstName: user.first_name ?? null,
lastName: user.last_name ?? null,
totalDistanceMeters: Number(statsResult.rows[0].total_distance_meters || 0),
totalRuns: Number(statsResult.rows[0].total_runs || 0),
totalCaptured: Number(statsResult.rows[0].total_captured || 0),
ownedNow: Number(ownedNowResult.rows[0].owned_now || 0),
lastRunAt: statsResult.rows[0].last_run_at ?? null
}
});
} catch (error) {
console.error('player profile error:', error);

return res.status(500).json({
ok: false,
error: error.message
});
}
});

// =========================================================
// БЛОК 8.2 GLOBAL LEADERBOARD
// =========================================================
app.get('/api/leaderboard/global', async (req, res) => {
try {
const limit = Number(req.query.limit) > 0
? Math.min(Number(req.query.limit), 100)
: 20;

const result = await pool.query(
`
select
u.telegram_id,
u.username,
u.first_name,
coalesce(owned.owned_now, 0) as owned_now,
coalesce(stats.total_distance_meters, 0) as total_distance_meters,
coalesce(stats.total_runs, 0) as total_runs,
coalesce(stats.total_captured, 0) as total_captured,
stats.last_run_at
from users u
left join (
select
owner_user_id,
count(*) as owned_now
from global_cell_ownership
group by owner_user_id
) owned on owned.owner_user_id = u.id
left join (
select
user_id,
sum(distance_meters) as total_distance_meters,
count(*) as total_runs,
sum(captured_count) as total_captured,
max(finished_at) as last_run_at
from runs
group by user_id
) stats on stats.user_id = u.id
where
coalesce(owned.owned_now, 0) > 0
or coalesce(stats.total_runs, 0) > 0
order by
coalesce(owned.owned_now, 0) desc,
coalesce(stats.total_captured, 0) desc,
coalesce(stats.total_distance_meters, 0) desc
limit $1
`,
[limit]
);

return res.json({
ok: true,
players: result.rows.map((row, index) => ({
rank: index + 1,
telegramId: row.telegram_id != null ? Number(row.telegram_id) : null,
username: row.username ?? null,
firstName: row.first_name ?? null,
ownedNow: Number(row.owned_now || 0),
totalDistanceMeters: Number(row.total_distance_meters || 0),
totalRuns: Number(row.total_runs || 0),
totalCaptured: Number(row.total_captured || 0),
lastRunAt: row.last_run_at ?? null
}))
});
} catch (error) {
console.error('global leaderboard error:', error);

return res.status(500).json({
ok: false,
error: error.message
});
}
});

// =========================================================
// БЛОК 8.3 VIEWPORT LEADERBOARD
// =========================================================
app.get('/api/leaderboard/viewport', async (req, res) => {
try {
const minLat = Number(req.query.minLat);
const maxLat = Number(req.query.maxLat);
const minLon = Number(req.query.minLon);
const maxLon = Number(req.query.maxLon);
const limit = Number(req.query.limit) > 0
? Math.min(Number(req.query.limit), 100)
: 20;

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
u.telegram_id,
u.username,
u.first_name,
count(*) as owned_in_viewport
from global_cell_ownership gco
join users u on u.id = gco.owner_user_id
where gco.grid_x between $1 and $2
and gco.grid_y between $3 and $4
group by u.id, u.telegram_id, u.username, u.first_name
order by owned_in_viewport desc, u.telegram_id asc
limit $5
`,
[range.minGridX, range.maxGridX, range.minGridY, range.maxGridY, limit]
);

return res.json({
ok: true,
players: result.rows.map((row, index) => ({
rank: index + 1,
telegramId: row.telegram_id != null ? Number(row.telegram_id) : null,
username: row.username ?? null,
firstName: row.first_name ?? null,
ownedInViewport: Number(row.owned_in_viewport || 0)
}))
});
} catch (error) {
console.error('viewport leaderboard error:', error);

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
