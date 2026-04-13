# Cierre Objetivo CodeQL - CVE-2021-44732

Fecha: 2026-04-10  
Herramienta: CodeQL 2.25.1  
Proyecto: mbedTLS  
Instancia: MBEDTLS-CVE-2021-44732

## Alcance

Analisis objetivo V/S para `CVE-2021-44732` usando SARIF y `src.zip` generados por el runner.

## Entradas

- Ground truth: `corpus/mbedtls/ground_truth.yaml`
- Fichero afectado: `library/ssl_srv.c`
- CWE / familia: `CWE-122` / `buffer-overflow`
- SARIF:
  - `results/raw/codeql/mbedtls/CVE-2021-44732/V.sarif`
  - `results/raw/codeql/mbedtls/CVE-2021-44732/S.sarif`
- DB snapshots:
  - `results/raw/codeql/mbedtls/CVE-2021-44732/db_V/src.zip`
  - `results/raw/codeql/mbedtls/CVE-2021-44732/db_S/src.zip`
- Metadatos:
  - `results/raw/codeql/mbedtls/CVE-2021-44732/V.meta.json`
  - `results/raw/codeql/mbedtls/CVE-2021-44732/S.meta.json`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 13:32:49,743`
- Fin V DB: `2026-04-10 13:44:49,915`
- Fin V analyze: `2026-04-10 13:50:08,271` (`306.07s`)
- Fin S DB: `2026-04-10 13:59:49,674`
- Fin S analyze: `2026-04-10 14:05:01,716` (`299.0s`)
- Fin instancia: `2026-04-10 14:05:04,401`

## Resumen cuantitativo V/S

- V total findings: `237`
- S total findings: `248`
- Reglas unicas V/S: `12 / 12`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `173`
- FP_S: `176`
- INTERSECTION: `128`
- ONLY_V: `45`
- ONLY_S: `48`
- Persistencia: `0.7399`

## Analisis en fichero afectado

- Findings en `library/ssl_srv.c`:
  - V: `0`
  - S: `0`
- Reglas en fichero afectado (V): `[]`
- Reglas en fichero afectado (S): `[]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `ok`
- Fichero encontrado en `src.zip`:
  - V: `.../repos/mbedtls_cve_2021_44732/library/ssl_srv.c`
  - S: `.../repos/mbedtls_cve_2021_44732/library/ssl_srv.c`
- Rangos parcheados detectados (lado S, muestra):
  - `[37-38], [201-201], [1225-1226], [1398-1398], [1854-1854], [1870-1870], [1974-1975], [1977-1978], [2019-2020], [2045-2046], ...`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0`
  - ONLY_S: `0`

## Veredicto objetivo

- Veredicto: `FN`
- Justificacion: Aunque se reconstruye correctamente el parche en `library/ssl_srv.c`, CodeQL no reporta hallazgos en el fichero afectado ni en ventana cercana a las lineas modificadas. Bajo el criterio del benchmark (senal en zona parcheada V/S), la instancia se clasifica como falso negativo.

## Notas

- Los archivos `V.error.json` y `S.error.json` presentes en la carpeta son residuos de un intento previo fallido; la corrida valida actual es la que genero `V.sarif`, `S.sarif` y `*.meta.json` con timestamps de 13:32-14:05.
- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
