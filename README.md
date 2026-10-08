# Feed CVE + KEV

Feed público del boletín Microsoft con cruce diario contra CISA KEV y EPSS.

## Deploy en Railway

```bash
# 1. Exportar CVEs del boletin actual desde la BDD local
node feed-publico/exportar_datos.js 2026-Sep

# 2. Ir al directorio e inicializar el repo
cd feed-publico
git init
git add -A
git commit -m "Feed CVE+KEV inicial"

# 3. Deployer en Railway
railway login
railway init
railway up
```

Railway detecta Node.js, corre `npm install` + `npm start` automáticamente.

## Variables de entorno (opcionales)

| Variable | Default | Descripción |
|---|---|---|
| `PORT` | 3000 | Puerto (Railway lo asigna solo) |
| `REFRESH_HOURS` | 6 | Cada cuántas horas refresca KEV/EPSS desde internet |

## Endpoints

| Ruta | Descripción |
|---|---|
| `GET /` | Índice con endpoints disponibles |
| `GET /cves` | Feed completo de CVEs con KEV y EPSS |
| `GET /cves/feed.json` | Alias (extensión explícita) |
| `GET /kev` | Solo CVEs que están en CISA KEV |
| `GET /stats` | Resumen numérico (conteos por severidad, tipo, criticidad) |
| `GET /salud` | Estado del servicio |
| `POST /refresh` | Forzar actualización de KEV/EPSS |

## Actualizar el boletín

Cuando salga un nuevo Patch Tuesday:

```bash
# Desde la raiz del proyecto principal
node feed-publico/exportar_datos.js 2026-Oct

# Commit y push (Railway redeploya automáticamente)
cd feed-publico
git add datos.json
git commit -m "Boletin 2026-Oct"
git push
```

## Consumir el feed

```python
import requests
feed = requests.get("https://tu-app.railway.app/cves").json()
for cve in feed["cves"]:
    if cve["kev"]["enKev"]:
        print(f"{cve['cve']} - KEV plazo: {cve['kev']['plazo']}")
```

```bash
curl -s https://tu-app.railway.app/kev | jq '.cves[] | {cve, plazo: .kev.plazo}'
```
