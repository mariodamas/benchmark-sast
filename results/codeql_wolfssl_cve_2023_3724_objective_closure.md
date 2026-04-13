# Cierre Objetivo CodeQL - wolfSSL CVE-2023-3724

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: wolfSSL
Instancia: WOLFSSL-CVE-2023-3724

## Alcance

Analisis objetivo V/S para `CVE-2023-3724` usando SARIF y `src.zip` del benchmark.

## Entradas

- Ground truth: `corpus/wolfssl/ground_truth.yaml`
- Fichero afectado: `src/tls13.c`
- CWE / familia: `CWE-121` / `buffer-overflow`
- Log de ejecucion: `results/logs/codeql_smoke_wolfssl_CVE-2023-3724_real.log`
- SARIF:
  - `results/raw/codeql/wolfssl/CVE-2023-3724/V.sarif`
  - `results/raw/codeql/wolfssl/CVE-2023-3724/S.sarif`
- DB snapshots:
  - `results/raw/codeql/wolfssl/CVE-2023-3724/db_V/src.zip`
  - `results/raw/codeql/wolfssl/CVE-2023-3724/db_S/src.zip`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 16:39:14,976`
- Fin V DB: `2026-04-10 16:59:31,790`
- Fin V analyze: `2026-04-10 17:07:38,899` (`468.75s`)
- Fin S DB: `2026-04-10 17:56:10,340`
- Fin S analyze: `2026-04-10 18:04:46,692` (`494.09s`)
- Fin instancia: `2026-04-10 18:04:51,965`

## Resumen cuantitativo V/S

- V total findings: `30`
- S total findings: `32`
- Reglas unicas V/S: `9 / 9`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `21`
- FP_S: `23`
- INTERSECTION: `8`
- ONLY_V: `13`
- ONLY_S: `15`
- Persistencia: `0.3810`

## Analisis en fichero afectado

- Findings en `src/tls13.c`:
  - V: `0`
  - S: `0`
- Reglas en fichero afectado (V): `[]`
- Reglas en fichero afectado (S): `[]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `ok`
- Fichero encontrado en `src.zip`:
  - V: `.../repos/wolfssl_w1/src/tls13.c`
  - S: `.../repos/wolfssl_w1/src/tls13.c`
- Rangos parcheados detectados (lado S, muestra):
  - `[80-80], [265-266], [273-273], [342-354], [417-417], [446-454], [480-481], [499-499], [528-534], [614-624], ...`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0`
  - ONLY_S: `0`

## Veredicto objetivo

- Veredicto: `FN`
- Justificacion: No hay findings en el fichero afectado ni en ventana cercana a las lineas parcheadas en V/S.

## Notas

- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
