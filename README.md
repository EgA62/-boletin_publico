# Feed CVE + KEV

Feed público del boletín Microsoft con cruce diario contra CISA KEV y EPSS.

## Deploy en Railway

```bash
cd feed-publico
git init && git add -A && git commit -m "init"
railway login && railway init && railway up
```

## Variables de entorno en Railway

| Variable | Default | Descripción |
|---|---|---|
| `PORT` | 8080 | Puerto (Railway lo asigna solo) |
| `REFRESH_HOURS` | 6 | Cada cuántas horas refresca KEV/EPSS desde internet |
| `API_TOKEN` | — | Token para proteger los endpoints de escritura. **Obligatorio en producción** |

## Autenticación

- **Lectura** (GET): pública, sin token
- **Escritura** (POST /actualizar, /refresh) y descarga cruda (GET /descargar): requiere `Authorization: Bearer <token>`

El token se define en Railway como variable de entorno `API_TOKEN`.

## Endpoints

| Ruta | Auth | Descripción |
|---|---|---|
| `GET /` | — | Índice con endpoints disponibles |
| `GET /cves?boletin=` | — | Feed completo; sin boletin = todos |
| `GET /cves/feed.json` | — | Alias |
| `GET /kev?boletin=` | — | Solo CVEs en CISA KEV |
| `GET /stats?boletin=` | — | Resumen numérico |
| `GET /boletines` | — | Boletines disponibles |
| `GET /salud` | — | Estado del servicio |
| `GET /descargar` | Token | Descarga datos.json crudo |
| `POST /actualizar` | Token | Empuja datos nuevos (body JSON) |
| `POST /refresh` | Token | Forzar refresh de KEV/EPSS |

## Actualizar datos desde tu máquina

### Opción 1: Script directo (sin git push)

```bash
FEED_TOKEN=tu_token node feed-publico/actualizar_remoto.js --todos
```

Te pregunta qué boletín(es) exportar, los saca de `boletin.db` y los empuja al servicio Railway. Los datos se actualizan en caliente, sin redeploy.

### Opción 2: Git push (redeploy completo)

```bash
node feed-publico/exportar_datos.js --todos
cd feed-publico && git add datos.json && git commit -m "Oct" && git push
```

### Opción 3: curl directo

```bash
curl -X POST https://tu-app.railway.app/actualizar \
  -H "Authorization: Bearer tu_token" \
  -H "Content-Type: application/json" \
  -d @feed-publico/datos.json
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
# Solo los que están en KEV
curl -s https://tu-app.railway.app/kev | jq '.cves[] | {cve, plazo: .kev.plazo}'

# Filtrar por boletín
curl -s "https://tu-app.railway.app/cves?boletin=2026-Sep" | jq '.meta.total'

# Forzar refresh de KEV/EPSS
curl -X POST https://tu-app.railway.app/refresh -H "Authorization: Bearer tu_token"
```
