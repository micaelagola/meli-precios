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

const MI_PROVIDER = 'meli_monitor';

async function getCreds(provider) {
  const r = await db.query(`SELECT key, value FROM provider_credentials WHERE provider=$1`, [provider]);
  const c = {};
  const rotas = [];
  for (const row of r.rows) {
    try { c[row.key] = decrypt(row.value); }
    catch { rotas.push(row.key); }
  }
  return { creds: c, rotas };
}

async function guardar(pares) {
  for (const [key, valor] of Object.entries(pares)) {
    if (valor == null) continue;
    await db.query(
      `INSERT INTO provider_credentials (provider, key, value, updated_at)
       VALUES ($1,$2,$3,now())
       ON CONFLICT (provider, key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`,
      [MI_PROVIDER, key, encrypt(String(valor))]
    );
  }
}

async function saveTokens(d) {
  await guardar({
    access_token: d.access_token,
    refresh_token: d.refresh_token ?? null,
    app_id: CREDS?.app_id,
    client_secret: CREDS?.client_secret,
  });
}

let TOKEN = null;
let CREDS = null;
let ultimoRefresh = 0;   // evita bucle de refresh ante 401/403 permanente

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
  if (!r.ok) {
    const detalle = await r.text();
    throw new Error(
      `No se pudo renovar el token de MercadoLibre (${r.status}): ${detalle}\n` +
      `-> Reconecta MercadoLibre desde la app SCD y volve a correr este job.`
    );
  }
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
    // 401 = vencido. 403 = MELI tambien lo usa para tokens invalidos (PolicyAgent).
    if ((r.status === 401 || r.status === 403) && Date.now() - ultimoRefresh > 60000) {
      ultimoRefresh = Date.now();
      await refreshToken();
      continue;
    }
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

const STATE_FILE = process.env.STATE_FILE || null;
let STATE = null;
if (STATE_FILE && fs.existsSync(STATE_FILE)) {
  try { STATE = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch {}
}

async function main() {
  const t0 = Date.now();
  await db.connect();
  // 1) Credenciales propias del monitor. 2) Si no tiene, las hereda de la app SCD.
  let origen = MI_PROVIDER;
  let { creds, rotas } = await getCreds(MI_PROVIDER);
  // Semilla desde los secrets de GitHub (independiente de la app SCD).
  if (!creds.refresh_token && process.env.MELI_REFRESH_TOKEN && process.env.MELI_APP_ID && process.env.MELI_CLIENT_SECRET) {
    origen = 'secrets de GitHub';
    creds = {
      app_id: process.env.MELI_APP_ID,
      client_secret: process.env.MELI_CLIENT_SECRET,
      refresh_token: process.env.MELI_REFRESH_TOKEN,
    };
    rotas = [];
  }
  if (!creds.refresh_token) {
    origen = 'meli (heredadas de SCD)';
    const scd = await getCreds('meli');
    creds = scd.creds; rotas = scd.rotas;
  }
  CREDS = creds;

  if (!CREDS.refresh_token || !CREDS.app_id || !CREDS.client_secret) {
    throw new Error(
      'Faltan credenciales de MercadoLibre' +
      (rotas.length ? ' (no se pudieron descifrar: ' + rotas.join(', ') + ' - guardadas con otra ENCRYPTION_KEY)' : '') +
      '.\n-> Reconecta MercadoLibre desde la app SCD y volve a correr este job: ' +
      'el monitor guarda su propia copia y deja de depender de eso.'
    );
  }
  console.log('[monitor] credenciales: ' + origen);

  TOKEN = CREDS.access_token ?? null;
  if (!TOKEN) await refreshToken();

  const seller = (await db.query(`SELECT value FROM app_settings WHERE key='meli_seller_id'`)).rows[0]?.value ?? '182591613';
  const SELLER_ID = Number(seller);
  console.log(`[monitor] seller ${SELLER_ID}`);

  // Cache de catálogos + checkpoint (reanudable si el proceso se corta)
  const catCache = new Map();
  const nickCache = new Map();
  if (STATE?.cat) {
    for (const [k, v] of Object.entries(STATE.cat)) catCache.set(k, v);
    console.log(`[monitor] checkpoint: ${catCache.size} catálogos ya consultados`);
  }
  function saveState() {
    if (!STATE_FILE) return;
    fs.writeFileSync(STATE_FILE, JSON.stringify({ items, cat: Object.fromEntries(catCache) }));
  }

  let items = [];
  if (STATE?.items?.length) {
    items = STATE.items;
    console.log(`[monitor] checkpoint: ${items.length} items ya relevados (salteo fases 1-2)`);
  } else {
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
  for (let i = 0; i < ids.length; i += 20) {
    const d = await apiGet(
      `/items?ids=${ids.slice(i, i + 20).join(',')}` +
      `&attributes=id,title,price,seller_custom_field,catalog_product_id,permalink,attributes,available_quantity,sold_quantity,date_created`
    );
    for (const it of d) {
      if (it.code !== 200 || !it.body) continue;
      const b = it.body;
      const skuRaw = b.seller_custom_field ||
        b.attributes?.find((a) => a.id === 'SELLER_SKU')?.value_name || null;
      const model = b.attributes?.find((a) => a.id === 'MODEL')?.value_name || null;
      const brand = b.attributes?.find((a) => a.id === 'BRAND')?.value_name || null;
      items.push({
        itemId: b.id,
        title: b.title,
        myPrice: b.price,
        skuRaw,
        model,
        brand,
        sku: normSku(skuRaw) || normSku(model),
        catalog: b.catalog_product_id || null,
        link: b.permalink || itemLink(b.id),
        stock: b.available_quantity ?? null,
        vendidos: b.sold_quantity ?? null,   // acumulado histórico de esa publicación
        creada: (b.date_created || '').slice(0, 10),
      });
    }
    await sleep(SLEEP_MS);
  }
  console.log(`[monitor] ${items.length} detalles obtenidos`);
  saveState();
  }  // fin fases 1-2

  // 2.5 Precio REAL propio: /items/{id}/sale_price incluye promociones activas.
  // El campo price del multiget es el precio "lleno" (tachado). Reanudable via spDone.
  {
    const pend = items.filter((it) => !it.spDone && !it.catalog);
    if (pend.length) console.log(`[monitor] sale_price pendientes: ${pend.length}`);
    let done25 = 0;
    const q25 = [...pend];
    async function spWorker() {
      while (q25.length) {
        const it = q25.shift();
        it.priceList = it.myPrice;   // precio lleno / tachado
        try {
          const sp = await apiGet(`/items/${it.itemId}/sale_price?context=channel_marketplace`);
          if (sp?.amount != null) it.myPrice = sp.amount;
          it.spDone = true;
        } catch { /* falló: queda pendiente para reintentar */ }
        done25++;
        if (done25 % 100 === 0) { saveState(); console.log(`[monitor] sale_price ${done25}/${pend.length}`); }
        await sleep(SLEEP_MS);
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, spWorker));
    saveState();
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

  // 3.5 Items SIN catálogo: buscar el producto de catálogo equivalente por título.
  // Matching estricto (marca + solapamiento de palabras) para no comparar peras con manzanas.
  const tokens = (str) => new Set(String(str).toUpperCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
    .split(/[^A-Z0-9]+/).filter((w) => w.length >= 3));
  const noCat = items.filter((x) => !x.catalog && x.catalogAprox === undefined);
  if (noCat.length) console.log(`[monitor] buscando catálogo aprox para ${noCat.length} items sin catálogo`);
  {
    let done35 = 0;
    const q35 = [...noCat];
    async function searchWorker() {
      while (q35.length) {
        const it = q35.shift();
        it.catalogAprox = null;
        try {
          const d = await apiGet(`/products/search?status=active&site_id=MLA&q=${encodeURIComponent(it.title.slice(0, 80))}`);
          const tt = tokens(it.title);
          for (const pr of (d.results ?? []).slice(0, 5)) {
            const pt = tokens(pr.name);
            const inter = [...tt].filter((w) => pt.has(w)).length;
            const score = inter / Math.min(tt.size, pt.size);
            const brandOk = !tt.has('LUSQTOFF') || pt.has('LUSQTOFF');
            if (score >= 0.6 && brandOk) { it.catalogAprox = pr.id; break; }
          }
        } catch {}
        done35++;
        if (done35 % 50 === 0) { saveState(); console.log(`[monitor] búsqueda aprox ${done35}/${noCat.length}`); }
        await sleep(SLEEP_MS);
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, searchWorker));
    saveState();
    console.log(`[monitor] matching aprox: ${items.filter((x) => x.catalogAprox).length} encontrados`);
  }

  const catalogIds = [...new Set(items.map((x) => x.catalog || x.catalogAprox).filter(Boolean))]
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

  // 3.9 Precio REAL propio desde el listado de catálogo.
  // Ese listado ya trae el precio con promociones aplicadas (price) y el lleno
  // (original_price), y es la MISMA fuente con la que leemos a los competidores,
  // así que la comparación queda pareja. Evita ~900 llamadas de sale_price.
  const sinPrecioReal = [];
  for (const it of items) {
    const cid = it.catalog || it.catalogAprox;
    const entry = cid ? catCache.get(cid) : null;
    const mio = entry?.results?.find((c) => c.item_id === it.itemId);
    if (mio) {
      it.priceList = mio.original_price ?? mio.price;   // precio lleno (tachado)
      it.myPrice = mio.price;                           // precio real que paga el cliente
    } else if (it.catalog && !it.spDone) {
      sinPrecioReal.push(it);   // no aparecí entre los 50 más baratos: consulto puntual
    }
  }
  if (sinPrecioReal.length) {
    console.log(`[monitor] sale_price puntual para ${sinPrecioReal.length} items de catálogo`);
    const q39 = [...sinPrecioReal];
    let hechos39 = 0;
    async function spWorker2() {
      while (q39.length) {
        const it = q39.shift();
        try {
          const sp = await apiGet(`/items/${it.itemId}/sale_price?context=channel_marketplace`);
          if (sp?.amount != null) { it.priceList = sp.regular_amount ?? it.myPrice; it.myPrice = sp.amount; it.spDone = true; }
        } catch {}
        if (++hechos39 % 100 === 0) saveState();
        await sleep(SLEEP_MS);
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, spWorker2));
    saveState();
  }

  // 4. Armar filas de salida
  const rows = [];
  for (const it of items) {
    const row = {
      ...it,
      matchType: it.catalog ? 'catalog' : (it.catalogAprox ? 'aprox' : null),
      totalSellers: null,   // vendedores del producto en catálogo
      bestPrice: null,      // precio más bajo del mercado (excluyéndonos)
      bestSeller: null,
      bestSellerId: null,
      bestLink: null,
      cheaperCount: null,   // cuántos venden más barato que nosotros
      winning: null,        // ¿somos el precio más bajo?
    };
    const cid = it.catalog || it.catalogAprox;
    if (cid && catCache.get(cid)) {
      const entry = catCache.get(cid);
      const others = entry.results.filter((c) => c.seller_id !== SELLER_ID && c.item_id !== it.itemId);
      row.totalSellers = entry.total;
      const cheaper = others.filter((c) => c.price < it.myPrice).sort((a, b) => a.price - b.price);
      row.cheaperCount = cheaper.length;
      row.winning = cheaper.length === 0;
      // Top 10 más baratos que nosotros (para el export a Excel)
      row.cheapers = cheaper.slice(0, 10).map((c) => ({
        price: c.price, sellerId: c.seller_id, link: itemLink(c.item_id),
      }));
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
  const bestIds = [...new Set([
    ...rows.filter((r) => r.bestSellerId).map((r) => r.bestSellerId),
    ...rows.flatMap((r) => (r.cheapers ?? []).map((c) => c.sellerId)),
  ])];
  console.log(`[monitor] resolviendo ${bestIds.length} nicknames`);
  const nq = [...bestIds];
  async function nickWorker() {
    while (nq.length) { await getNick(nq.shift()); await sleep(SLEEP_MS); }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, nickWorker));
  for (const r of rows) {
    if (r.bestSellerId) r.bestSeller = nickCache.get(r.bestSellerId);
    for (const c of r.cheapers ?? []) c.seller = nickCache.get(c.sellerId) ?? String(c.sellerId);
  }

  // ─── 7. VENTAS: cuándo vendió por última vez cada SKU ──────────────────────
  // Fuente 1 (preferida): la API de órdenes de MELI, con fechas exactas.
  // Fuente 2 (respaldo):  historial propio. Cada corrida anotamos el acumulado de
  //   ventas de cada publicación; si sube, ese día hubo venta. No pide permisos.
  const HIST_FILE = path.join(__dirname, '..', 'docs', 'historial.json');
  const hoyISO = new Date().toISOString().slice(0, 10);
  const ventas = { fuente: null, motivo: null, desde: null, porSku: {} };

  try {
    const desde = new Date(Date.now() - 90 * 864e5).toISOString();
    const porItem = new Map();
    let offset = 0, total = null;
    while (offset < 3000) {
      const d = await apiGet(`/orders/search?seller=${SELLER_ID}&order.date_created.from=${desde}&sort=date_desc&offset=${offset}&limit=50`);
      total = d.paging?.total ?? 0;
      for (const o of (d.results ?? [])) {
        const fecha = (o.date_closed || o.date_created || '').slice(0, 10);
        for (const oi of (o.order_items ?? [])) {
          const id = oi.item?.id;
          if (!id || !fecha) continue;
          const prev = porItem.get(id);
          if (!prev || fecha > prev) porItem.set(id, fecha);
        }
      }
      offset += 50;
      if (offset >= total) break;
      await sleep(SLEEP_MS);
    }
    ventas.fuente = 'meli';
    ventas.desde = desde.slice(0, 10);
    for (const it of items) { const f = porItem.get(it.itemId); if (f) it.ultimaVenta = f; }
    console.log(`[monitor] ventas desde MELI: ${total} órdenes en 90 días`);
  } catch (e) {
    ventas.fuente = 'historial';
    ventas.motivo = String(e.message || e).slice(0, 120);
    console.log(`[monitor] órdenes no disponibles -> uso historial propio`);
  }

  let hist = {};
  try { hist = JSON.parse(fs.readFileSync(HIST_FILE, 'utf8')); } catch {}
  for (const it of items) {
    if (it.vendidos == null) continue;
    const prev = hist[it.itemId];
    if (!prev) hist[it.itemId] = { q: it.vendidos, ult: hoyISO, desde: hoyISO };
    else if (it.vendidos > prev.q) hist[it.itemId] = { q: it.vendidos, ult: hoyISO, desde: prev.desde };
    else hist[it.itemId] = { q: prev.q, ult: prev.ult, desde: prev.desde };
  }
  const vivos = new Set(items.map((x) => x.itemId));
  for (const k of Object.keys(hist)) if (!vivos.has(k)) delete hist[k];
  fs.mkdirSync(path.dirname(HIST_FILE), { recursive: true });
  fs.writeFileSync(HIST_FILE, JSON.stringify(hist));

  if (ventas.fuente === 'historial') {
    const desdes = Object.values(hist).map((h) => h.desde).filter(Boolean).sort();
    ventas.desde = desdes[0] ?? hoyISO;
    for (const it of items) { const h = hist[it.itemId]; if (h) it.ultimaVenta = h.ult; }
  }

  // Agrupo por SKU: un producto está parado solo si NINGUNA de sus publicaciones vendió.
  // Los SKU de OUTLET quedan afuera.
  for (const it of items) {
    const sku = it.sku;
    if (!sku) continue;
    const texto = `${it.skuRaw ?? ''} ${it.model ?? ''} ${it.title ?? ''}`.toUpperCase();
    if (texto.includes('OUTLET')) continue;
    const v = ventas.porSku[sku] ?? { ultima: null, pubs: 0, vendidos: 0, desde: null, creada: null };
    v.pubs++;
    v.vendidos += it.vendidos ?? 0;
    if (it.creada && (!v.creada || it.creada > v.creada)) v.creada = it.creada;
    if (it.ultimaVenta && (!v.ultima || it.ultimaVenta > v.ultima)) v.ultima = it.ultimaVenta;
    const dd = hist[it.itemId]?.desde;
    if (dd && (!v.desde || dd < v.desde)) v.desde = dd;
    ventas.porSku[sku] = v;
  }
  console.log(`[monitor] ventas (${ventas.fuente}): ${Object.keys(ventas.porSku).length} SKU`);

  // 6. Guardar
  const out = {
    generatedAt: new Date().toISOString(),
    sellerId: SELLER_ID,
    totalItems: rows.length,
    withCatalog: rows.filter((r) => r.catalog).length,
    withAprox: rows.filter((r) => !r.catalog && r.catalogAprox).length,
    ventas,
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
