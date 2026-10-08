#!/usr/bin/env node
// Exporta los CVEs de boletin.db a datos.json para el servicio de Railway.
//
// Uso interactivo (pregunta mes o todos):
//   node feed-publico/exportar_datos.js
//
// Uso directo:
//   node feed-publico/exportar_datos.js 2026-Sep     boletin especifico
//   node feed-publico/exportar_datos.js --todos       todos los boletines

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const RAIZ = path.join(__dirname, '..');

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

function exportar(ids) {
  const boletines = [];
  let totalCves = 0;
  for (const id of ids) {
    const meta = db.prepare('SELECT * FROM boletin WHERE id = ?').get(id);
    if (!meta) { console.warn(`  Boletin ${id} no encontrado, saltando.`); continue; }
    const filas = db.prepare('SELECT * FROM v_cve_actual WHERE boletin = ? ORDER BY cvss DESC, cve ASC').all(id);
    boletines.push({
      boletin: meta.id, titulo: meta.titulo,
      patchTuesday: meta.patch_tuesday, totalCve: filas.length,
    });
    totalCves += filas.length;
  }

  const todasFilas = db.prepare(
    `SELECT * FROM v_cve_actual WHERE boletin IN (${ids.map(() => '?').join(',')}) ORDER BY cvss DESC, cve ASC`
  ).all(...ids);

  const datos = {
    meta: {
      exportado: new Date().toISOString(),
      totalCves: totalCves,
      boletines,
    },
    cves: todasFilas.map(formatearCve),
  };

  const salida = path.join(__dirname, 'datos.json');
  fs.writeFileSync(salida, JSON.stringify(datos, null, 2), 'utf8');
  console.log(`\n  ${totalCves} CVEs de ${ids.length} boletin(es) -> feed-publico/datos.json`);
  for (const b of boletines) console.log(`    ${b.boletin}: ${b.totalCve} CVEs`);
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

  console.error(`No entendi "${limpio}".`);
  process.exit(1);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--todos') || args.includes('--all')) {
    const ids = listarBoletines().map((b) => b.id);
    exportar(ids);
  } else if (args.length && /^\d{4}-[A-Z][a-z]{2}$/.test(args[0])) {
    exportar([args[0]]);
  } else {
    const ids = await preguntar();
    exportar(ids);
  }

  db.close();
}

main().catch((e) => { console.error(e); process.exit(1); });
