#!/usr/bin/env node
// Exporta CVEs de boletin.db y los empuja al feed de Railway.
//
// Uso:
//   node feed-publico/actualizar_remoto.js                   ultimo boletin
//   node feed-publico/actualizar_remoto.js --todos            todos los boletines
//   node feed-publico/actualizar_remoto.js 2026-Oct           boletin especifico
//
// Variables de entorno:
//   FEED_URL    URL del servicio Railway (default: https://boletinpublico-production.up.railway.app)
//   FEED_TOKEN  token de autenticacion (obligatorio)

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const RAIZ = path.join(__dirname, '..');
const FEED_URL = process.env.FEED_URL || 'https://boletinpublico-production.up.railway.app';
const FEED_TOKEN = process.env.FEED_TOKEN || '';

let DatabaseSync;
try { ({ DatabaseSync } = require('node:sqlite')); } catch {
  console.error('node:sqlite no disponible (requiere Node 24+).');
  process.exit(1);
}

const rutaBdd = path.join(RAIZ, 'datos', 'boletin.db');
if (!fs.existsSync(rutaBdd)) { console.error(`No se encuentra ${rutaBdd}`); process.exit(1); }

const db = new DatabaseSync(rutaBdd);
db.exec('PRAGMA busy_timeout = 5000');

function listarBoletines() {
  return db.prepare('SELECT id, titulo, total_cve FROM boletin ORDER BY id DESC').all();
}

function formatearCve(f) {
  return {
    cve: f.cve, titulo: f.titulo || '', producto: f.producto || '',
    tipo: f.tipo || '', severidad: f.severidad || '', cvss: f.cvss,
    vector: f.vector || '', criticidad: f.criticidad || '',
    explotado: f.explotado === 'SI', divulgado: f.divulgado === 'SI',
    epss: f.epss, epssPercentil: f.epss_percentil, publicado: f.publicado || '',
    boletin: f.boletin,
  };
}

function construirPayload(ids) {
  const boletines = [];
  for (const id of ids) {
    const meta = db.prepare('SELECT * FROM boletin WHERE id = ?').get(id);
    if (!meta) continue;
    const n = db.prepare('SELECT COUNT(*) AS n FROM cve WHERE boletin = ?').get(id).n;
    boletines.push({ boletin: meta.id, titulo: meta.titulo, patchTuesday: meta.patch_tuesday, totalCve: n });
  }
  const filas = db.prepare(
    `SELECT * FROM v_cve_actual WHERE boletin IN (${ids.map(() => '?').join(',')}) ORDER BY cvss DESC, cve ASC`
  ).all(...ids);
  return {
    meta: { exportado: new Date().toISOString(), totalCves: filas.length, boletines },
    cves: filas.map(formatearCve),
  };
}

async function preguntar() {
  const bols = listarBoletines();
  console.log('\nBoletines disponibles:\n');
  bols.forEach((b, i) => console.log(`  ${i + 1}. ${b.id}  (${b.total_cve} CVEs)`));
  console.log(`\n  0. TODOS (${bols.reduce((s, b) => s + b.total_cve, 0)} CVEs)\n`);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const resp = await new Promise((r) => rl.question('Elige (numero o nombre del mes): ', r));
  rl.close();
  const limpio = resp.trim();
  if (limpio === '0' || limpio.toLowerCase() === 'todos') return bols.map((b) => b.id);
  const num = Number(limpio);
  if (Number.isInteger(num) && num >= 1 && num <= bols.length) return [bols[num - 1].id];
  const match = bols.find((b) => b.id === limpio);
  if (match) return [match.id];
  console.error(`No entendi "${limpio}".`); process.exit(1);
}

async function enviar(payload) {
  const url = `${FEED_URL.replace(/\/$/, '')}/actualizar`;
  console.log(`\nEnviando ${payload.cves.length} CVEs a ${url}...`);
  const r = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(FEED_TOKEN ? { 'Authorization': `Bearer ${FEED_TOKEN}` } : {}),
    },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    console.error(`  Error HTTP ${r.status}: ${body.error || r.statusText}`);
    process.exit(1);
  }
  console.log(`  ${body.mensaje || 'OK'}`);
  console.log(`  Ultimo refresh KEV/EPSS: ${body.ultimoRefresh || '?'}`);
}

async function main() {
  if (!FEED_TOKEN) {
    console.warn('[AVISO] FEED_TOKEN no definido. Si el servicio tiene API_TOKEN, la peticion fallara.');
  }

  const args = process.argv.slice(2);
  let ids;

  if (args.includes('--todos') || args.includes('--all')) {
    ids = listarBoletines().map((b) => b.id);
  } else if (args.length && /^\d{4}-[A-Z][a-z]{2}$/.test(args[0])) {
    ids = [args[0]];
  } else {
    ids = await preguntar();
  }

  const payload = construirPayload(ids);
  console.log(`\n  ${payload.cves.length} CVEs de ${ids.length} boletin(es)`);
  for (const b of payload.meta.boletines) console.log(`    ${b.boletin}: ${b.totalCve} CVEs`);

  await enviar(payload);
  db.close();
}

main().catch((e) => { console.error(e); process.exit(1); });
