#!/usr/bin/env node
// Exporta los CVEs de boletin.db a datos.json para el servicio de Railway.
//
// Uso (desde la raiz del proyecto):
//   node feed-publico/exportar_datos.js              ultimo boletin
//   node feed-publico/exportar_datos.js 2026-Sep     boletin especifico
//
// Despues: cd feed-publico && git add datos.json && git push
// Railway redeploya automaticamente y el feed se actualiza.

const fs = require('fs');
const path = require('path');

const RAIZ = path.join(__dirname, '..');
const MESES3 = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

let DatabaseSync;
try { ({ DatabaseSync } = require('node:sqlite')); } catch {
  console.error('node:sqlite no disponible (requiere Node 24+).');
  process.exit(1);
}

const boletin = process.argv[2] || null;
const rutaBdd = path.join(RAIZ, 'datos', 'boletin.db');

if (!fs.existsSync(rutaBdd)) {
  console.error(`No se encuentra ${rutaBdd}`);
  process.exit(1);
}

const db = new DatabaseSync(rutaBdd);
db.exec('PRAGMA busy_timeout = 5000');

let id = boletin;
if (!id) {
  const ultimo = db.prepare('SELECT id FROM boletin ORDER BY id DESC LIMIT 1').get();
  if (!ultimo) { console.error('No hay boletines en la BDD.'); process.exit(1); }
  id = ultimo.id;
}

const meta = db.prepare('SELECT * FROM boletin WHERE id = ?').get(id);
if (!meta) { console.error(`Boletin ${id} no encontrado.`); process.exit(1); }

const filas = db.prepare(`
  SELECT * FROM v_cve_actual WHERE boletin = ? ORDER BY cvss DESC, cve ASC
`).all(id);

const datos = {
  meta: {
    boletin: meta.id,
    titulo: meta.titulo,
    patchTuesday: meta.patch_tuesday,
    exportado: new Date().toISOString(),
  },
  cves: filas.map((f) => ({
    cve: f.cve,
    titulo: f.titulo || '',
    producto: f.producto || '',
    tipo: f.tipo || '',
    severidad: f.severidad || '',
    cvss: f.cvss,
    vector: f.vector || '',
    criticidad: f.criticidad || '',
    explotado: f.explotado === 'SI',
    divulgado: f.divulgado === 'SI',
    epss: f.epss,
    epssPercentil: f.epss_percentil,
    publicado: f.publicado || '',
  })),
};

const salida = path.join(__dirname, 'datos.json');
fs.writeFileSync(salida, JSON.stringify(datos, null, 2), 'utf8');
db.close();

console.log(`Exportados ${datos.cves.length} CVEs de ${id} -> feed-publico/datos.json`);
