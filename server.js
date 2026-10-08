const express = require('express');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const REFRESH_MS = Number(process.env.REFRESH_HOURS || 6) * 3600 * 1000;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss?cve=';

// ── Estado en memoria ────────────────────────────────────────────────────────
let datosBase = [];     // CVEs crudos del boletin (de datos.json)
let metaBase = {};      // meta del boletin
let kevMapa = null;     // Map<cve, {nombre, fecha, plazo, ransomware, accion}>
let epssMapa = null;    // Map<cve, {epss, percentil}>
let ultimoRefresh = null;
let refreshEnCurso = false;

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
  console.log(`Cargados ${datosBase.length} CVEs del boletin ${metaBase.boletin || '?'}`);
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
    const ids = datosBase.map((c) => c.cve);
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

function feedCompleto() {
  const cves = datosBase.map(enriquecer);
  const enKev = cves.filter((c) => c.kev.enKev);
  const explotados = cves.filter((c) => c.explotado || c.kev.enKev);
  const divulgados = cves.filter((c) => c.divulgado);
  return {
    meta: {
      ...metaBase,
      generado: new Date().toISOString(),
      ultimoRefreshKev: ultimoRefresh,
      total: cves.length,
      enKev: enKev.length,
      explotados: explotados.length,
      divulgados: divulgados.length,
    },
    cves,
  };
}

// ── Express ──────────────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');

app.use((_req, res, next) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'public, max-age=300',
  });
  next();
});

app.get('/', (_req, res) => {
  res.json({
    nombre: 'feed-cve-kev',
    descripcion: 'Feed publico de CVE del boletin Microsoft con cruce CISA KEV y EPSS',
    boletin: metaBase.boletin || null,
    ultimoRefresh: ultimoRefresh,
    endpoints: {
      'GET /cves': 'feed completo (JSON)',
      'GET /cves/feed.json': 'alias',
      'GET /kev': 'solo CVEs en CISA KEV',
      'GET /stats': 'resumen numerico',
      'GET /salud': 'estado del servicio',
      'POST /refresh': 'forzar actualizacion de KEV/EPSS',
    },
  });
});

function serveFeed(req, res) {
  res.json(feedCompleto());
}
app.get('/cves', serveFeed);
app.get('/cves/feed.json', serveFeed);

app.get('/kev', (_req, res) => {
  const cves = datosBase.map(enriquecer).filter((c) => c.kev.enKev);
  res.json({
    meta: {
      ...metaBase,
      generado: new Date().toISOString(),
      ultimoRefreshKev: ultimoRefresh,
      total: cves.length,
    },
    cves,
  });
});

app.get('/stats', (_req, res) => {
  const cves = datosBase.map(enriquecer);
  const porSeveridad = {};
  const porTipo = {};
  const porCriticidad = {};
  for (const c of cves) {
    porSeveridad[c.severidad || 'N/A'] = (porSeveridad[c.severidad || 'N/A'] || 0) + 1;
    porTipo[c.tipo || 'N/A'] = (porTipo[c.tipo || 'N/A'] || 0) + 1;
    porCriticidad[c.criticidad || 'N/A'] = (porCriticidad[c.criticidad || 'N/A'] || 0) + 1;
  }
  res.json({
    meta: { ...metaBase, generado: new Date().toISOString(), ultimoRefreshKev: ultimoRefresh },
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

app.get('/salud', (_req, res) => {
  res.json({
    ok: true,
    boletin: metaBase.boletin || null,
    totalCves: datosBase.length,
    ultimoRefresh: ultimoRefresh,
    refreshCadaHoras: REFRESH_MS / 3600000,
    uptime: Math.round(process.uptime()),
  });
});

app.post('/refresh', async (_req, res) => {
  if (refreshEnCurso) return res.json({ mensaje: 'Refresh ya en curso.' });
  await refrescar();
  res.json({ mensaje: 'Refresh completado.', ultimoRefresh });
});

// ── Arranque ─────────────────────────────────────────────────────────────────
cargarDatos();
refrescar().then(() => {
  app.listen(PORT, () => {
    console.log(`Feed CVE+KEV escuchando en puerto ${PORT}`);
    console.log(`Refresh automatico cada ${REFRESH_MS / 3600000}h`);
  });
  setInterval(refrescar, REFRESH_MS);
});
