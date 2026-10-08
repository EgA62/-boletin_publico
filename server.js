const express = require('express');
const crypto = require('crypto');
const zlib = require('zlib');
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

// Cache pre-computado — se reconstruye al cargar datos o refrescar KEV/EPSS
let cacheEnriquecido = [];        // todos los CVEs enriquecidos
let indiceCve = new Map();        // CVE-ID -> objeto enriquecido
let indiceBoletin = new Map();    // boletin -> [cves]
let cacheEtag = '';               // hash para 304
let cacheJsonAll = null;          // Buffer gzip del feed completo
let cacheJsonKev = null;          // Buffer gzip del feed solo KEV
let cachePorBoletin = new Map();  // boletin -> Buffer gzip

function reconstruirCache() {
  const t0 = Date.now();
  cacheEnriquecido = datosBase.map(enriquecer);
  indiceCve = new Map();
  indiceBoletin = new Map();
  for (const c of cacheEnriquecido) {
    indiceCve.set(c.cve, c);
    let arr = indiceBoletin.get(c.boletin);
    if (!arr) { arr = []; indiceBoletin.set(c.boletin, arr); }
    arr.push(c);
  }

  // Pre-serializar respuestas frecuentes con gzip
  const allJson = JSON.stringify({ meta: buildMeta(cacheEnriquecido, null), cves: cacheEnriquecido });
  cacheEtag = crypto.createHash('md5').update(allJson).digest('hex');
  cacheJsonAll = zlib.gzipSync(allJson);

  const kevCves = cacheEnriquecido.filter(c => c.kev.enKev);
  cacheJsonKev = zlib.gzipSync(JSON.stringify({ meta: buildMeta(kevCves, null), cves: kevCves }));

  cachePorBoletin = new Map();
  for (const [bol, cves] of indiceBoletin) {
    cachePorBoletin.set(bol, zlib.gzipSync(JSON.stringify({ meta: buildMeta(cves, bol), cves })));
  }
  console.log(`  Cache reconstruido en ${Date.now() - t0}ms (${cacheEnriquecido.length} CVEs, etag ${cacheEtag.slice(0, 8)})`);
}

// ── Auth ─────────────────────────────────────────────────────────────────────
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
  console.log(`Cargados ${datosBase.length} CVEs de ${bols.length} boletin(es): ${bols.map(b => b.boletin).join(', ') || '?'}`);
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
      nombre: v.vulnerabilityName, fecha: v.dateAdded, plazo: v.dueDate,
      ransomware: v.knownRansomwareCampaignUse === 'Known', accion: v.requiredAction,
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
        m.set(d.cve, { epss: Math.round(Number(d.epss) * 10000) / 10000, percentil: Math.round(Number(d.percentile) * 10000) / 10000 });
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
  } catch (e) { console.warn('  KEV fallo:', e.message); }
  try {
    const ids = [...new Set(datosBase.map(c => c.cve))];
    epssMapa = await descargarEpss(ids);
    console.log(`  EPSS: ${epssMapa.size} scores`);
  } catch (e) { console.warn('  EPSS fallo:', e.message); }
  ultimoRefresh = new Date().toISOString();
  refreshEnCurso = false;
  console.log(`  Refresh completado en ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  reconstruirCache();
}

// ── Enriquecer un CVE con KEV/EPSS ───────────────────────────────────────────
function enriquecer(cve) {
  const k = kevMapa ? kevMapa.get(cve.cve) : null;
  const e = epssMapa ? epssMapa.get(cve.cve) : null;
  return {
    cve: cve.cve, titulo: cve.titulo, producto: cve.producto,
    tipo: cve.tipo, severidad: cve.severidad, cvss: cve.cvss,
    vector: cve.vector, criticidad: cve.criticidad,
    explotado: cve.explotado, divulgado: cve.divulgado,
    epss: e ? e.epss : (cve.epss ?? null),
    epssPercentil: e ? e.percentil : (cve.epssPercentil ?? null),
    publicado: cve.publicado, boletin: cve.boletin,
    kev: {
      enKev: !!k, fechaAgregado: k ? k.fecha : null,
      plazo: k ? k.plazo : null, ransomware: k ? k.ransomware : false,
      accion: k ? k.accion : null,
    },
  };
}

function buildMeta(cves, filtro) {
  const enKev = cves.filter(c => c.kev.enKev);
  const explotados = cves.filter(c => c.explotado || c.kev.enKev);
  const divulgados = cves.filter(c => c.divulgado);
  return {
    boletines: metaBase.boletines || [], filtro: filtro || null,
    generado: new Date().toISOString(), ultimoRefreshKev: ultimoRefresh, ultimaActualizacion,
    total: cves.length, enKev: enKev.length, explotados: explotados.length, divulgados: divulgados.length,
  };
}

// ── Helpers de respuesta ────────────────────────────────────────────────────
function enviarGzip(req, res, buffer, etag) {
  if (etag && req.headers['if-none-match'] === `"${etag}"`) {
    return res.status(304).end();
  }
  res.set('Content-Type', 'application/json; charset=utf-8');
  if (etag) res.set('ETag', `"${etag}"`);
  if ((req.headers['accept-encoding'] || '').includes('gzip')) {
    res.set('Content-Encoding', 'gzip');
    return res.send(buffer);
  }
  res.send(zlib.gunzipSync(buffer));
}

function filtrarCampos(cves, campos) {
  if (!campos) return cves;
  const keys = campos.split(',').map(k => k.trim()).filter(Boolean);
  if (!keys.length) return cves;
  return cves.map(c => {
    const o = {};
    for (const k of keys) {
      if (k in c) o[k] = c[k];
    }
    return o;
  });
}

function paginar(cves, req) {
  const limit = Math.min(Math.max(Number(req.query.limit) || 0, 0), 5000) || cves.length;
  const offset = Math.max(Number(req.query.offset) || 0, 0);
  const paginado = cves.slice(offset, offset + limit);
  return { cves: paginado, total: cves.length, limit, offset, hayMas: offset + limit < cves.length };
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

// ── Landing page ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const accept = req.headers.accept || '';
  if (accept.includes('application/json') && !accept.includes('text/html')) {
    const bols = (metaBase.boletines || []).map(b => b.boletin);
    return res.json({
      nombre: 'feed-cve-kev', totalCves: datosBase.length, boletines: bols,
      ultimoRefresh, ultimaActualizacion,
      endpoints: {
        'GET /cves': 'feed completo (paginable: limit, offset, campos)',
        'GET /cve/:id': 'lookup un CVE',
        'POST /buscar': 'buscar lote de CVE-IDs',
        'GET /kev': 'solo CVEs en KEV',
        'GET /stats': 'resumen numerico',
        'GET /boletines': 'lista de boletines',
      },
    });
  }
  const bols = metaBase.boletines || [];
  const enKev = cacheEnriquecido.filter(c => c.kev.enKev).length;
  const explotados = cacheEnriquecido.filter(c => c.explotado || c.kev.enKev).length;
  const opcionesBol = bols.map(b => `<option value="${b.boletin}">${b.boletin} (${b.totalCve} CVEs)</option>`).join('');
  res.type('html').send(`<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Feed CVE + KEV</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--card:#f7f7f8;--brd:#e0e0e0;--accent:#800080;--accent2:#6b006b;--badge:#eee;--kev:#c0392b;--ok:#27ae60}
@media(prefers-color-scheme:dark){:root{--bg:#18181b;--fg:#e4e4e7;--card:#27272a;--brd:#3f3f46;--badge:#3f3f46;--accent:#c084fc;--accent2:#a855f7}}
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5;padding:0 16px}
.wrap{max-width:720px;margin:0 auto;padding:2rem 0 3rem}
h1{font-size:1.5rem;font-weight:700;margin-bottom:.25rem}
.sub{color:#888;font-size:.875rem;margin-bottom:1.5rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin-bottom:1.5rem}
.card{background:var(--card);border:1px solid var(--brd);border-radius:10px;padding:1rem;text-align:center}
.card .n{font-size:1.75rem;font-weight:700}
.card .l{font-size:.75rem;color:#888;text-transform:uppercase;letter-spacing:.04em}
.card.kev .n{color:var(--kev)}
.card.ok .n{color:var(--ok)}
.sep{border:0;border-top:1px solid var(--brd);margin:1.5rem 0}
h2{font-size:1.1rem;font-weight:600;margin-bottom:.75rem}
.row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem}
select,button{font:inherit;border-radius:8px;padding:.5rem 1rem;border:1px solid var(--brd);background:var(--card);color:var(--fg);cursor:pointer}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600}
button.primary:hover{background:var(--accent2)}
.ep{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
.ep a{font-size:.8rem;padding:.35rem .7rem;border-radius:6px;background:var(--badge);color:var(--fg);text-decoration:none;font-family:monospace}
.ep a:hover{background:var(--accent);color:#fff}
.ts{font-size:.75rem;color:#888;margin-top:1.5rem}
code{font-size:.8rem;background:var(--badge);padding:.15rem .4rem;border-radius:4px}
.api{margin-top:1rem;font-size:.85rem;color:#888}
.drop{border:2px dashed var(--brd);border-radius:12px;padding:2rem;text-align:center;cursor:pointer;transition:border-color .2s,background .2s}
.drop:hover,.drop.over{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 6%,transparent)}
.drop input{display:none}
.drop .ico{font-size:2rem;margin-bottom:.5rem}
.drop p{font-size:.9rem;color:#888}
#cmpStatus{margin-top:.75rem;font-size:.85rem}
#cmpCards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.5rem;margin:1rem 0}
#cmpCards .card{padding:.75rem}
#cmpCards .card .n{font-size:1.4rem}
#cmpTable{width:100%;border-collapse:collapse;font-size:.8rem;margin:1rem 0;display:none}
#cmpTable th{text-align:left;padding:.4rem .5rem;border-bottom:2px solid var(--brd);position:sticky;top:0;background:var(--bg)}
#cmpTable td{padding:.35rem .5rem;border-bottom:1px solid var(--brd);white-space:nowrap}
#cmpTable tr:hover td{background:color-mix(in srgb,var(--accent) 8%,transparent)}
.tWrap{max-height:400px;overflow:auto;border:1px solid var(--brd);border-radius:8px}
.badge{display:inline-block;font-size:.7rem;padding:.1rem .4rem;border-radius:4px;font-weight:600}
.badge.si{background:#c0392b;color:#fff}
.badge.no{background:var(--badge);color:#888}
.badge.ms{background:var(--accent);color:#fff}
.badge.fuera{background:var(--badge);color:#888}
#cmpBtns{display:none;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}
</style></head><body><div class="wrap">
<h1>Feed CVE + KEV</h1>
<p class="sub">Boletin Microsoft &middot; cruce CISA KEV y EPSS &middot; actualizado cada 6h</p>
<div class="cards">
  <div class="card"><div class="n">${datosBase.length}</div><div class="l">CVEs totales</div></div>
  <div class="card"><div class="n">${bols.length}</div><div class="l">Boletines</div></div>
  <div class="card kev"><div class="n">${enKev}</div><div class="l">En CISA KEV</div></div>
  <div class="card"><div class="n">${explotados}</div><div class="l">Explotados</div></div>
</div>
<hr class="sep">
<h2>Descargar</h2>
<div class="row">
  <select id="bol"><option value="">Todos los boletines</option>${opcionesBol}</select>
  <button class="primary" onclick="dl('cves')">Descargar JSON</button>
  <button onclick="dl('kev')">Solo KEV</button>
  <button onclick="dl('stats')">Resumen</button>
</div>
<hr class="sep">
<h2>Comparar Excel</h2>
<p style="font-size:.85rem;color:#888;margin-bottom:.75rem">Sube un Excel con CVE-IDs y en segundos sabes cuales estan en boletines Microsoft, KEV y EPSS.</p>
<div class="drop" id="dropZone" onclick="document.getElementById('xlFile').click()">
  <div class="ico">&#128196;</div>
  <p>Arrastra un .xlsx / .csv o haz clic para seleccionar</p>
  <input type="file" id="xlFile" accept=".xlsx,.xls,.csv">
</div>
<div id="cmpStatus"></div>
<div id="cmpCards"></div>
<div id="cmpBtns">
  <button class="primary" onclick="exportarXlsx()">Descargar Excel enriquecido</button>
  <button onclick="exportarJson()">Descargar JSON</button>
  <button onclick="limpiar()">Limpiar</button>
</div>
<div class="tWrap"><table id="cmpTable"><thead><tr>
  <th>CVE</th><th>Microsoft</th><th>Severidad</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>Producto</th>
</tr></thead><tbody id="cmpBody"></tbody></table></div>
<hr class="sep">
<h2>Endpoints</h2>
<div class="ep">
  <a href="/cves">/cves</a>
  <a href="/cve/CVE-2026-0001">/cve/:id</a>
  <a href="/kev">/kev</a>
  <a href="/stats">/stats</a>
  <a href="/boletines">/boletines</a>
  <a href="/salud">/salud</a>
  <a href="/cves/feed.json">/cves/feed.json</a>
</div>
<p class="api">Paginacion: <code>/cves?limit=100&amp;offset=0</code><br>
Campos: <code>/cves?campos=cve,severidad,cvss,kev</code><br>
Lote: <code>POST /buscar</code> con <code>{"cves":["CVE-..."]}</code></p>
<p class="ts">Ultimo refresh KEV/EPSS: ${ultimoRefresh || '—'}<br>Ultima actualizacion de datos: ${ultimaActualizacion || '—'}</p>
</div>
<script>
function dl(ep){
  const b=document.getElementById('bol').value;
  const q=b?'?boletin='+encodeURIComponent(b):'';
  const url='/'+ep+q;
  const a=document.createElement('a');
  a.href=url;a.download=ep+(b?'_'+b:'')+'.json';
  document.body.appendChild(a);a.click();a.remove();
}

/* ── Comparar Excel ──────────────────────────────────────────────────────── */
let ultimoResultado=null;
const dropZone=document.getElementById('dropZone');
const xlFile=document.getElementById('xlFile');
const status=document.getElementById('cmpStatus');
const cardsDiv=document.getElementById('cmpCards');
const tabla=document.getElementById('cmpTable');
const tbody=document.getElementById('cmpBody');
const btns=document.getElementById('cmpBtns');

dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('over')});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('over'));
dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('over');if(e.dataTransfer.files.length)procesar(e.dataTransfer.files[0])});
xlFile.addEventListener('change',()=>{if(xlFile.files.length)procesar(xlFile.files[0])});

function extraerCves(wb){
  const rx=/CVE-\\d{4}-\\d{4,}/gi;
  const set=new Set();
  for(const name of wb.SheetNames){
    const ws=wb.Sheets[name];
    const csv=XLSX.utils.sheet_to_csv(ws);
    let m;while((m=rx.exec(csv))!==null)set.add(m[0].toUpperCase());
  }
  return[...set];
}

async function procesar(file){
  const t0=performance.now();
  status.textContent='Leyendo archivo...';
  cardsDiv.innerHTML='';tbody.innerHTML='';tabla.style.display='none';btns.style.display='none';
  try{
    const buf=await file.arrayBuffer();
    const wb=XLSX.read(buf,{type:'array'});
    const ids=extraerCves(wb);
    if(!ids.length){status.textContent='No se encontraron CVE-IDs en el archivo.';return}
    status.textContent='Consultando '+ids.length+' CVEs...';
    const r=await fetch('/buscar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cves:ids})});
    const data=await r.json();
    const ms=Math.round(performance.now()-t0);
    ultimoResultado=data;
    const enKev=data.cves.filter(c=>c.kev&&c.kev.enKev).length;
    const expl=data.cves.filter(c=>c.explotado||c.kev&&c.kev.enKev).length;
    status.innerHTML='<strong>'+ids.length+'</strong> CVEs procesados en <strong>'+ms+'ms</strong>';
    cardsDiv.innerHTML=
      '<div class="card"><div class="n">'+ids.length+'</div><div class="l">CVEs en archivo</div></div>'+
      '<div class="card" style="border-color:var(--accent)"><div class="n" style="color:var(--accent)">'+data.total+'</div><div class="l">En Microsoft</div></div>'+
      '<div class="card"><div class="n" style="color:#888">'+data.noEncontrados+'</div><div class="l">No encontrados</div></div>'+
      '<div class="card kev"><div class="n">'+enKev+'</div><div class="l">En KEV</div></div>'+
      '<div class="card"><div class="n">'+expl+'</div><div class="l">Explotados</div></div>';
    renderTabla(data,ids);
    btns.style.display='flex';
  }catch(e){status.textContent='Error: '+e.message}
}

function renderTabla(data,todosIds){
  tbody.innerHTML='';
  const mapa=new Map();
  for(const c of data.cves)mapa.set(c.cve,c);
  const filas=todosIds.map(id=>{
    const c=mapa.get(id);
    if(c)return{id,ms:true,sev:c.severidad||'',cvss:c.cvss??'',kev:c.kev&&c.kev.enKev,epss:c.epss??'',prod:c.producto||'',obj:c};
    return{id,ms:false,sev:'',cvss:'',kev:false,epss:'',prod:'',obj:null};
  });
  filas.sort((a,b)=>{
    if(a.kev!==b.kev)return a.kev?-1:1;
    if(a.ms!==b.ms)return a.ms?-1:1;
    return(b.cvss||0)-(a.cvss||0);
  });
  const max=Math.min(filas.length,500);
  for(let i=0;i<max;i++){
    const f=filas[i];
    const tr=document.createElement('tr');
    tr.innerHTML=
      '<td><strong>'+f.id+'</strong></td>'+
      '<td>'+(f.ms?'<span class="badge ms">SI</span>':'<span class="badge fuera">NO</span>')+'</td>'+
      '<td>'+f.sev+'</td>'+
      '<td>'+(f.cvss||'—')+'</td>'+
      '<td>'+(f.kev?'<span class="badge si">KEV</span>':'<span class="badge no">—</span>')+'</td>'+
      '<td>'+(f.epss!==''&&f.epss!==null?(f.epss*100).toFixed(2)+'%':'—')+'</td>'+
      '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">'+f.prod+'</td>';
    tbody.appendChild(tr);
  }
  if(filas.length>500){
    const tr=document.createElement('tr');
    tr.innerHTML='<td colspan="7" style="text-align:center;color:#888;padding:.75rem">... '+(filas.length-500)+' mas (descarga el Excel para ver todos)</td>';
    tbody.appendChild(tr);
  }
  tabla.style.display='table';
}

function exportarXlsx(){
  if(!ultimoResultado)return;
  const rows=ultimoResultado.cves.map(c=>({
    CVE:c.cve,Titulo:c.titulo||'',Producto:c.producto||'',
    Severidad:c.severidad||'',CVSS:c.cvss??'',Tipo:c.tipo||'',
    Explotado:c.explotado?'SI':'NO',Divulgado:c.divulgado?'SI':'NO',
    EnKEV:c.kev&&c.kev.enKev?'SI':'NO',
    KEV_Plazo:c.kev&&c.kev.plazo||'',
    KEV_Ransomware:c.kev&&c.kev.ransomware?'SI':'NO',
    EPSS:c.epss??'',EPSS_Percentil:c.epssPercentil??'',
    Boletin:c.boletin||''
  }));
  if(ultimoResultado.faltantes&&ultimoResultado.faltantes.length){
    for(const id of ultimoResultado.faltantes){
      rows.push({CVE:id,Titulo:'NO ENCONTRADO EN MICROSOFT',Producto:'',Severidad:'',CVSS:'',Tipo:'',Explotado:'',Divulgado:'',EnKEV:'',KEV_Plazo:'',KEV_Ransomware:'',EPSS:'',EPSS_Percentil:'',Boletin:''});
    }
  }
  const ws=XLSX.utils.json_to_sheet(rows);
  const cols=[{wch:18},{wch:40},{wch:30},{wch:10},{wch:6},{wch:20},{wch:9},{wch:9},{wch:6},{wch:12},{wch:14},{wch:8},{wch:12},{wch:10}];
  ws['!cols']=cols;
  const wb=XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb,ws,'Comparacion');
  XLSX.writeFile(wb,'comparacion_cve.xlsx');
}

function exportarJson(){
  if(!ultimoResultado)return;
  const blob=new Blob([JSON.stringify(ultimoResultado,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='comparacion_cve.json';
  document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(a.href);
}

function limpiar(){
  ultimoResultado=null;status.textContent='';cardsDiv.innerHTML='';
  tbody.innerHTML='';tabla.style.display='none';btns.style.display='none';xlFile.value='';
}
</script></body></html>`);
});

// ── Feed completo (cache gzip + ETag + paginacion) ──────────────────────────
function serveFeed(req, res) {
  const bol = req.query.boletin;
  const hasPagination = req.query.limit || req.query.offset;
  const hasCampos = req.query.campos;

  // Fast path: sin filtros → cache gzip pre-computado con ETag
  if (!bol && !hasPagination && !hasCampos) {
    return enviarGzip(req, res, cacheJsonAll, cacheEtag);
  }

  // Cache por boletin sin paginacion ni campos
  if (bol && !hasPagination && !hasCampos && cachePorBoletin.has(bol)) {
    return enviarGzip(req, res, cachePorBoletin.get(bol), null);
  }

  // Fallback con paginacion y/o campos
  let cves = bol ? (indiceBoletin.get(bol) || []) : cacheEnriquecido;
  const p = paginar(cves, req);
  cves = filtrarCampos(p.cves, req.query.campos);
  res.json({ meta: { ...buildMeta(bol ? (indiceBoletin.get(bol) || []) : cacheEnriquecido, bol), ...{ limit: p.limit, offset: p.offset, hayMas: p.hayMas } }, cves });
}
app.get('/cves', serveFeed);
app.get('/cves/feed.json', serveFeed);

// ── Lookup individual por CVE-ID ────────────────────────────────────────────
app.get('/cve/:id', (req, res) => {
  const c = indiceCve.get(req.params.id);
  if (!c) return res.status(404).json({ error: `${req.params.id} no encontrado` });
  res.json(c);
});

// ── Busqueda por lote de CVE-IDs ────────────────────────────────────────────
app.post('/buscar', (req, res) => {
  const ids = req.body?.cves;
  if (!Array.isArray(ids)) return res.status(400).json({ error: 'Body: {"cves":["CVE-2026-..."]}' });
  const encontrados = [];
  const noEncontrados = [];
  for (const id of ids) {
    const c = indiceCve.get(id);
    if (c) encontrados.push(c);
    else noEncontrados.push(id);
  }
  res.json({ total: encontrados.length, noEncontrados: noEncontrados.length, cves: encontrados, faltantes: noEncontrados });
});

// ── Solo KEV (cache gzip) ───────────────────────────────────────────────────
app.get('/kev', (req, res) => {
  const bol = req.query.boletin;
  if (!bol && !req.query.limit && !req.query.offset && !req.query.campos) {
    return enviarGzip(req, res, cacheJsonKev, null);
  }
  let cves = bol ? (indiceBoletin.get(bol) || []) : cacheEnriquecido;
  cves = cves.filter(c => c.kev.enKev);
  const p = paginar(cves, req);
  cves = filtrarCampos(p.cves, req.query.campos);
  res.json({ meta: buildMeta(cves, bol), cves });
});

app.get('/stats', (req, res) => {
  const bol = req.query.boletin;
  const cves = bol ? (indiceBoletin.get(bol) || []) : cacheEnriquecido;
  const porSeveridad = {};
  const porTipo = {};
  const porCriticidad = {};
  for (const c of cves) {
    porSeveridad[c.severidad || 'N/A'] = (porSeveridad[c.severidad || 'N/A'] || 0) + 1;
    porTipo[c.tipo || 'N/A'] = (porTipo[c.tipo || 'N/A'] || 0) + 1;
    porCriticidad[c.criticidad || 'N/A'] = (porCriticidad[c.criticidad || 'N/A'] || 0) + 1;
  }
  res.json({
    meta: buildMeta(cves, bol),
    resumen: {
      total: cves.length, enKev: cves.filter(c => c.kev.enKev).length,
      explotados: cves.filter(c => c.explotado || c.kev.enKev).length,
      divulgados: cves.filter(c => c.divulgado).length,
      ransomware: cves.filter(c => c.kev.ransomware).length,
    },
    porSeveridad, porTipo, porCriticidad,
  });
});

app.get('/boletines', (_req, res) => {
  res.json({ boletines: metaBase.boletines || [] });
});

app.get('/salud', (_req, res) => {
  res.json({
    ok: true, totalCves: datosBase.length,
    boletines: (metaBase.boletines || []).length,
    ultimoRefresh, ultimaActualizacion,
    refreshCadaHoras: REFRESH_MS / 3600000,
    authActivo: !!API_TOKEN, uptime: Math.round(process.uptime()),
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
    ultimaActualizacion, ultimoRefresh,
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
