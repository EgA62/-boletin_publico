const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const REFRESH_MS = Number(process.env.REFRESH_HOURS || 6) * 3600 * 1000;
const API_TOKEN = process.env.API_TOKEN || null;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss?cve=';

// ── Estado en memoria ────────────────────────────────────────────────────────
let datosBase = [];
let metaBase = {};
let kevMapa = null;
let epssMapa = null;
let ultimoRefresh = null;
let ultimaActualizacion = null;
let refreshEnCurso = false;

// ── Auth ─────────────────────────────────────────────────────────────────────
// Lectura: publica. Escritura (POST /actualizar, /refresh, /descargar):
// requiere Authorization: Bearer <token> si API_TOKEN esta definido.
function authRequerido(req, res, next) {
  if (!API_TOKEN) return next();
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : null;
  if (!token || !safeCompare(token, API_TOKEN)) {
    return res.status(401).json({ error: 'Token invalido o ausente. Envia Authorization: Bearer <token>' });
  }
  next();
}
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ── Cargar datos base ────────────────────────────────────────────────────────
function cargarDatos() {
  const ruta = path.join(__dirname, 'datos.json');
  if (!fs.existsSync(ruta)) {
    console.error('datos.json no encontrado. Ejecuta: node exportar_datos.js');
    process.exit(1);
  }
  const raw = JSON.parse(fs.readFileSync(ruta, 'utf8'));
  datosBase = raw.cves || [];
  metaBase = raw.meta || {};
  ultimaActualizacion = metaBase.exportado || null;
  const bols = metaBase.boletines || [];
  console.log(`Cargados ${datosBase.length} CVEs de ${bols.length} boletin(es): ${bols.map((b) => b.boletin).join(', ') || '?'}`);
}

function recargarDesdePayload(payload) {
  datosBase = payload.cves || [];
  metaBase = payload.meta || {};
  ultimaActualizacion = new Date().toISOString();
  fs.writeFileSync(path.join(__dirname, 'datos.json'), JSON.stringify(payload, null, 2), 'utf8');
  const bols = metaBase.boletines || [];
  console.log(`[${ultimaActualizacion}] Datos actualizados: ${datosBase.length} CVEs de ${bols.length} boletin(es)`);
}

// ── KEV desde CISA ───────────────────────────────────────────────────────────
async function descargarKev() {
  const r = await fetch(KEV_URL);
  if (!r.ok) throw new Error(`KEV HTTP ${r.status}`);
  const data = await r.json();
  const m = new Map();
  for (const v of data.vulnerabilities) {
    m.set(v.cveID, {
      nombre: v.vulnerabilityName,
      fecha: v.dateAdded,
      plazo: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
      accion: v.requiredAction,
    });
  }
  return { mapa: m, version: data.catalogVersion, fecha: String(data.dateReleased || '').slice(0, 10), total: m.size };
}

// ── EPSS desde FIRST ─────────────────────────────────────────────────────────
async function descargarEpss(cves) {
  const m = new Map();
  for (let i = 0; i < cves.length; i += 100) {
    const lote = cves.slice(i, i + 100);
    try {
      const r = await fetch(EPSS_URL + lote.join(','));
      if (!r.ok) continue;
      const data = await r.json();
      for (const d of data.data || []) {
        m.set(d.cve, {
          epss: Math.round(Number(d.epss) * 10000) / 10000,
          percentil: Math.round(Number(d.percentile) * 10000) / 10000,
        });
      }
    } catch { /* lote falla, sigue */ }
  }
  return m;
}

// ── Refresh completo ─────────────────────────────────────────────────────────
async function refrescar() {
  if (refreshEnCurso) return;
  refreshEnCurso = true;
  const t0 = Date.now();
  console.log(`[${new Date().toISOString()}] Refrescando KEV + EPSS...`);
  try {
    const kev = await descargarKev();
    kevMapa = kev.mapa;
    console.log(`  KEV: ${kev.total} vulns (v${kev.version}, ${kev.fecha})`);
  } catch (e) {
    console.warn('  KEV fallo:', e.message);
  }
  try {
    const ids = [...new Set(datosBase.map((c) => c.cve))];
    epssMapa = await descargarEpss(ids);
    console.log(`  EPSS: ${epssMapa.size} scores`);
  } catch (e) {
    console.warn('  EPSS fallo:', e.message);
  }
  ultimoRefresh = new Date().toISOString();
  refreshEnCurso = false;
  console.log(`  Refresh completado en ${((Date.now() - t0) / 1000).toFixed(1)}s`);
}

// ── Enriquecer un CVE con KEV/EPSS ───────────────────────────────────────────
function enriquecer(cve) {
  const k = kevMapa ? kevMapa.get(cve.cve) : null;
  const e = epssMapa ? epssMapa.get(cve.cve) : null;
  return {
    ...cve,
    epss: e ? e.epss : (cve.epss ?? null),
    epssPercentil: e ? e.percentil : (cve.epssPercentil ?? null),
    kev: {
      enKev: !!k,
      fechaAgregado: k ? k.fecha : null,
      plazo: k ? k.plazo : null,
      ransomware: k ? k.ransomware : false,
      accion: k ? k.accion : null,
    },
  };
}

function filtrar(req) {
  const b = req.query.boletin;
  const base = b ? datosBase.filter((c) => c.boletin === b) : datosBase;
  return base.map(enriquecer);
}

function buildMeta(cves, filtro) {
  const enKev = cves.filter((c) => c.kev.enKev);
  const explotados = cves.filter((c) => c.explotado || c.kev.enKev);
  const divulgados = cves.filter((c) => c.divulgado);
  const bols = metaBase.boletines || [];
  return {
    boletines: bols,
    filtro: filtro || null,
    generado: new Date().toISOString(),
    ultimoRefreshKev: ultimoRefresh,
    ultimaActualizacion,
    total: cves.length,
    enKev: enKev.length,
    explotados: explotados.length,
    divulgados: divulgados.length,
  };
}

// ── Express ──────────────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10mb' }));

app.use((_req, res, next) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS, POST',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Cache-Control': 'public, max-age=300',
  });
  next();
});
app.options('*', (_req, res) => res.sendStatus(204));

// ── Lectura: publica ─────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  const bols = (metaBase.boletines || []).map((b) => b.boletin);
  res.json({
    nombre: 'feed-cve-kev',
    descripcion: 'Feed publico de CVE del boletin Microsoft con cruce CISA KEV y EPSS',
    totalCves: datosBase.length,
    boletines: bols,
    ultimoRefresh: ultimoRefresh,
    ultimaActualizacion,
    auth: API_TOKEN ? 'POST requiere Authorization: Bearer <token>' : 'sin proteccion (definir API_TOKEN en env)',
    endpoints: {
      lectura: {
        'GET /cves?boletin=': 'feed completo; sin boletin = todos',
        'GET /cves/feed.json?boletin=': 'alias',
        'GET /kev?boletin=': 'solo CVEs en CISA KEV',
        'GET /stats?boletin=': 'resumen numerico',
        'GET /boletines': 'lista de boletines disponibles',
        'GET /salud': 'estado del servicio',
        'GET /descargar': 'descarga datos.json crudo (requiere token)',
      },
      escritura: {
        'POST /actualizar': 'empuja datos nuevos (body = {meta, cves}); requiere token',
        'POST /refresh': 'forzar actualizacion de KEV/EPSS; requiere token',
      },
    },
  });
});

function serveFeed(req, res) {
  const cves = filtrar(req);
  res.json({ meta: buildMeta(cves, req.query.boletin), cves });
}
app.get('/cves', serveFeed);
app.get('/cves/feed.json', serveFeed);

app.get('/kev', (req, res) => {
  const cves = filtrar(req).filter((c) => c.kev.enKev);
  res.json({ meta: buildMeta(cves, req.query.boletin), cves });
});

app.get('/stats', (req, res) => {
  const cves = filtrar(req);
  const porSeveridad = {};
  const porTipo = {};
  const porCriticidad = {};
  for (const c of cves) {
    porSeveridad[c.severidad || 'N/A'] = (porSeveridad[c.severidad || 'N/A'] || 0) + 1;
    porTipo[c.tipo || 'N/A'] = (porTipo[c.tipo || 'N/A'] || 0) + 1;
    porCriticidad[c.criticidad || 'N/A'] = (porCriticidad[c.criticidad || 'N/A'] || 0) + 1;
  }
  res.json({
    meta: buildMeta(cves, req.query.boletin),
    resumen: {
      total: cves.length,
      enKev: cves.filter((c) => c.kev.enKev).length,
      explotados: cves.filter((c) => c.explotado || c.kev.enKev).length,
      divulgados: cves.filter((c) => c.divulgado).length,
      ransomware: cves.filter((c) => c.kev.ransomware).length,
    },
    porSeveridad,
    porTipo,
    porCriticidad,
  });
});

app.get('/boletines', (_req, res) => {
  res.json({ boletines: metaBase.boletines || [] });
});

app.get('/salud', (_req, res) => {
  res.json({
    ok: true,
    totalCves: datosBase.length,
    boletines: (metaBase.boletines || []).length,
    ultimoRefresh: ultimoRefresh,
    ultimaActualizacion,
    refreshCadaHoras: REFRESH_MS / 3600000,
    authActivo: !!API_TOKEN,
    uptime: Math.round(process.uptime()),
  });
});

// ── Escritura: requiere token ────────────────────────────────────────────────

app.post('/actualizar', authRequerido, async (req, res) => {
  const body = req.body;
  if (!body || !Array.isArray(body.cves) || !body.meta) {
    return res.status(400).json({ error: 'Body debe ser {meta: {boletines: [...]}, cves: [...]}' });
  }
  recargarDesdePayload(body);
  await refrescar();
  res.json({
    ok: true,
    mensaje: `Actualizados ${datosBase.length} CVEs de ${(metaBase.boletines || []).length} boletin(es).`,
    ultimaActualizacion,
    ultimoRefresh,
  });
});

app.post('/refresh', authRequerido, async (_req, res) => {
  if (refreshEnCurso) return res.json({ mensaje: 'Refresh ya en curso.' });
  await refrescar();
  res.json({ ok: true, mensaje: 'Refresh completado.', ultimoRefresh });
});

app.get('/descargar', authRequerido, (_req, res) => {
  res.json({ meta: metaBase, cves: datosBase });
});

// ── Arranque ─────────────────────────────────────────────────────────────────
cargarDatos();
if (!API_TOKEN) console.warn('[AVISO] API_TOKEN no definido: endpoints de escritura sin proteccion.');
refrescar().then(() => {
  app.listen(PORT, () => {
    console.log(`Feed CVE+KEV escuchando en puerto ${PORT}`);
    console.log(`Refresh automatico cada ${REFRESH_MS / 3600000}h`);
  });
  setInterval(refrescar, REFRESH_MS);
});
