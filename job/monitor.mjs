/**
 * MELI Precios — Monitor diario de competencia
 *
 * Flujo:
 *  1. Lee credenciales MELI (cifradas) desde la DB compartida con SCD.
 *  2. Usa el access_token; si venció, lo renueva y PERSISTE el nuevo
 *     refresh_token en la DB (crítico: los refresh tokens son de un solo uso).
 *  3. Escanea TODAS las publicaciones activas del seller.
 *  4. Para cada publicación vinculada a catálogo, obtiene todos los
 *     vendedores del mismo producto (precio, seller, link).
 *  5. Genera docs/data.json para el dashboard estático.
 *
 * Env requerido: DATABASE_URL, ENCRYPTION_KEY
 * Uso: node job/monitor.mjs
 */

import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_FILE = path.join(__dirname, '..', 'docs', 'data.json');
const API = 'https://api.mercadolibre.com';
const CONCURRENCY = 5;
const SLEEP_MS = 120;

// ─── Config desde env (con autoload de ../.env si faltan) ───────────────────
if (!process.env.DATABASE_URL || !process.env.ENCRYPTION_KEY) {
  try {
    const envTxt = fs.readFileSync(path.join(__dirname, '..', '.env'), 'utf8');
    for (const line of envTxt.split('\n')) {
      const m = line.match(/^\s*([A-Z_]+)\s*=\s*"?([^"\r]*)"?\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
    }
  } catch {}
}
const DATABASE_URL = process.env.DATABASE_URL;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!DATABASE_URL || !ENCRYPTION_KEY) {
  console.error('Faltan env vars: DATABASE_URL y/o ENCRYPTION_KEY');
  process.exit(1);
}

// ─── Crypto (idéntico a packages/shared/src/crypto.ts de SCD) ────────────────
const KEY = scryptSync(ENCRYPTION_KEY, 'scd-cred-salt', 32);
const PREFIX = 'enc:v1:';
function decrypt(ct) {
  if (!ct.startsWith(PREFIX)) return ct;
  const [iv, tag, enc] = ct.slice(PREFIX.length).split(':');
  const d = createDecipheriv('aes-256-gcm', KEY, Buffer.from(iv, 'hex'));
  d.setAuthTag(Buffer.from(tag, 'hex'));
  return d.update(enc, 'hex', 'utf8') + d.final('utf8');
}
function encrypt(pt) {
  const iv = randomBytes(16);
  const ci = createCipheriv('aes-256-gcm', KEY, iv);
  let e = ci.update(pt, 'utf8', 'hex');
  e += ci.final('hex');
  return PREFIX + iv.toString('hex') + ':' + ci.getAuthTag().toString('hex') + ':' + e;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ─── DB: credenciales compartidas ────────────────────────────────────────────
const db = new pg.Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function getCreds() {
  const r = await db.query(`SELECT key, value FROM provider_credentials WHERE provider='meli'`);
  const c = {};
  for (const row of r.rows) {
    try { c[row.key] = decrypt(row.value); } catch { c[row.key] = row.value; }
  }
  return c;
}

async function saveTokens(d) {
  await db.query(
    `UPDATE provider_credentials SET value=$1, updated_at=now() WHERE provider='meli' AND key='access_token'`,
    [encrypt(d.access_token)]
  );
  if (d.refresh_token) {
    await db.query(
      `UPDATE provider_credentials SET value=$1, updated_at=now() WHERE provider='meli' AND key='refresh_token'`,
      [encrypt(d.refresh_token)]
    );
  }
}

let TOKEN = null;
let CREDS = null;

async function refreshToken() {
  const r = await fetch(`${API}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: CREDS.app_id,
      client_secret: CREDS.client_secret,
      refresh_token: CREDS.refresh_token,
    }),
  });
  if (!r.ok) throw new Error(`Refresh token falló: ${r.status} ${await r.text()}`);
  const d = await r.json();
  await saveTokens(d);              // persistir ANTES de usar (rotación de un solo uso)
  CREDS.refresh_token = d.refresh_token ?? CREDS.refresh_token;
  TOKEN = d.access_token;
  console.log('[token] renovado y persistido en DB');
  return TOKEN;
}

async function apiGet(p, retries = 3) {
  for (let i = 0; ; i++) {
    let r;
    try {
      r = await fetch(API + p, {
        headers: { Authorization: `Bearer ${TOKEN}` },
        signal: AbortSignal.timeout(15000),   // sin esto, un socket colgado congela el worker
      });
    } catch (e) {
      if (i < retries) { await sleep(1000 * (i + 1)); continue; }
      throw new Error(`MELI red/timeout: ${p} (${e.name})`);
    }
    if (r.status === 401) { await refreshToken(); continue; }
    if (r.status === 429) { await sleep(2000 * (i + 1)); if (i < retries + 2) continue; }
    if (!r.ok) {
      if (i < retries) { await sleep(800 * (i + 1)); continue; }
      throw new Error(`MELI ${r.status}: ${p}`);
    }
    return r.json();
  }
}

// ─── Helpers de dominio ──────────────────────────────────────────────────────
const normSku = (s) => (s ? String(s).toUpperCase().replace(/[^A-Z0-9]/g, '') : null);
const itemLink = (id) => `https://articulo.mercadolibre.com.ar/${id.slice(0, 3)}-${id.slice(3)}`;

async function main() {
  const t0 = Date.now();
  await db.connect();
  CREDS = await getCreds();
  TOKEN = CREDS.access_token;
  if (!TOKEN) await refreshToken();

  const seller = (await db.query(`SELECT value FROM app_settings WHERE key='meli_seller_id'`)).rows[0]?.value ?? '182591613';
  const SELLER_ID = Number(seller);
  console.log(`[monitor] seller ${SELLER_ID}`);

  // 1. Scan de publicaciones activas (search_type=scan soporta >1000)
  let ids = [];
  let scroll = null;
  while (true) {
    const p = `/users/${SELLER_ID}/items/search?status=active&search_type=scan&limit=100` +
      (scroll ? `&scroll_id=${encodeURIComponent(scroll)}` : '');
    const d = await apiGet(p);
    if (!d.results?.length) break;
    ids.push(...d.results);
    scroll = d.scroll_id;
    if (ids.length >= d.paging.total) break;
    await sleep(SLEEP_MS);
  }
  ids = [...new Set(ids)];
  console.log(`[monitor] ${ids.length} publicaciones activas`);

  // 2. Detalles (multiget de a 20)
  const items = [];
  for (let i = 0; i < ids.length; i += 20) {
    const d = await apiGet(
      `/items?ids=${ids.slice(i, i + 20).join(',')}` +
      `&attributes=id,title,price,seller_custom_field,catalog_product_id,permalink,attributes,available_quantity`
    );
    for (const it of d) {
      if (it.code !== 200 || !it.body) continue;
      const b = it.body;
      const skuRaw = b.seller_custom_field ||
        b.attributes?.find((a) => a.id === 'SELLER_SKU')?.value_name || null;
      const model = b.attributes?.find((a) => a.id === 'MODEL')?.value_name || null;
      items.push({
        itemId: b.id,
        title: b.title,
        myPrice: b.price,
        skuRaw,
        model,
        sku: normSku(skuRaw) || normSku(model),
        catalog: b.catalog_product_id || null,
        link: b.permalink || itemLink(b.id),
        stock: b.available_quantity ?? null,
      });
    }
    await sleep(SLEEP_MS);
  }
  console.log(`[monitor] ${items.length} detalles obtenidos`);

  // 3. Competencia por producto de catálogo (con cache: varios items → mismo catálogo)
  // Checkpoint opcional (STATE_FILE): permite reanudar si el proceso se corta.
  const STATE_FILE = process.env.STATE_FILE || null;
  const catCache = new Map();
  const nickCache = new Map();
  if (STATE_FILE && fs.existsSync(STATE_FILE)) {
    try {
      const st = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      for (const [k, v] of Object.entries(st.cat ?? {})) catCache.set(k, v);
      console.log(`[monitor] checkpoint: ${catCache.size} catálogos ya consultados`);
    } catch {}
  }
  function saveState() {
    if (!STATE_FILE) return;
    fs.writeFileSync(STATE_FILE, JSON.stringify({ cat: Object.fromEntries(catCache) }));
  }
  async function getNick(sellerId) {
    if (nickCache.has(sellerId)) return nickCache.get(sellerId);
    try {
      const u = await apiGet(`/users/${sellerId}`);
      nickCache.set(sellerId, u.nickname ?? String(sellerId));
    } catch { nickCache.set(sellerId, String(sellerId)); }
    return nickCache.get(sellerId);
  }

  async function getCompetitors(catalogId) {
    if (catCache.has(catalogId)) return catCache.get(catalogId);
    // 1 sola llamada: los resultados vienen ordenados por precio ascendente,
    // los 50 más baratos alcanzan para detectar quién nos pisa.
    const d = await apiGet(`/products/${catalogId}/items?limit=50`);
    const entry = { total: d.paging?.total ?? d.results?.length ?? 0, results: d.results ?? [] };
    catCache.set(catalogId, entry);
    return entry;
  }

  const catalogIds = [...new Set(items.filter((x) => x.catalog).map((x) => x.catalog))]
    .filter((cid) => !catCache.has(cid));
  console.log(`[monitor] ${catalogIds.length} productos de catálogo a consultar`);

  let done = 0;
  const queue = [...catalogIds];
  async function worker() {
    while (queue.length) {
      const cid = queue.shift();
      try { await getCompetitors(cid); } catch (e) { console.error(`[warn] catálogo ${cid}: ${e.message}`); catCache.set(cid, null); }
      done++;
      if (done % 50 === 0) { saveState(); console.log(`[monitor] catálogos ${done}/${catalogIds.length}`); }
      await sleep(SLEEP_MS);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  saveState();

  // 4. Armar filas de salida
  const rows = [];
  for (const it of items) {
    const row = {
      ...it,
      totalSellers: null,   // vendedores del producto en catálogo
      bestPrice: null,      // precio más bajo del mercado (excluyéndonos)
      bestSeller: null,
      bestSellerId: null,
      bestLink: null,
      cheaperCount: null,   // cuántos venden más barato que nosotros
      winning: null,        // ¿somos el precio más bajo?
    };
    if (it.catalog && catCache.get(it.catalog)) {
      const entry = catCache.get(it.catalog);
      const others = entry.results.filter((c) => c.seller_id !== SELLER_ID);
      row.totalSellers = entry.total;
      row.cheaperCount = others.filter((c) => c.price < it.myPrice).length;
      row.winning = row.cheaperCount === 0;
      if (others.length) {
        const best = others.reduce((a, b) => (a.price <= b.price ? a : b));
        row.bestPrice = best.price;
        row.bestSellerId = best.seller_id;
        row.bestLink = itemLink(best.item_id);
      }
    }
    rows.push(row);
  }

  // 5. Nicknames solo de los "mejores" vendedores (con cache)
  const bestIds = [...new Set(rows.filter((r) => r.bestSellerId).map((r) => r.bestSellerId))];
  console.log(`[monitor] resolviendo ${bestIds.length} nicknames`);
  const nq = [...bestIds];
  async function nickWorker() {
    while (nq.length) { await getNick(nq.shift()); await sleep(SLEEP_MS); }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, nickWorker));
  for (const r of rows) if (r.bestSellerId) r.bestSeller = nickCache.get(r.bestSellerId);

  // 6. Guardar
  const out = {
    generatedAt: new Date().toISOString(),
    sellerId: SELLER_ID,
    totalItems: rows.length,
    withCatalog: rows.filter((r) => r.catalog).length,
    rows,
  };
  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(out));
  if (STATE_FILE && fs.existsSync(STATE_FILE)) fs.unlinkSync(STATE_FILE);
  console.log(`[monitor] OK -> ${OUT_FILE} (${rows.length} filas, ${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  await db.end();
}

main().catch(async (e) => {
  console.error('[monitor] FALLO:', e);
  try { await db.end(); } catch {}
  process.exit(1);
});
