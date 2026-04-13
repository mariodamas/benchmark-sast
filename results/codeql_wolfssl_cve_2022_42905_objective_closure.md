# Cierre Objetivo CodeQL - wolfSSL CVE-2022-42905

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: wolfSSL
Instancia: WOLFSSL-CVE-2022-42905

## Alcance

Analisis objetivo V/S para `CVE-2022-42905` usando SARIF y `src.zip` del benchmark.

## Entradas

- Ground truth: `corpus/wolfssl/ground_truth.yaml`
- Fichero afectado: `wolfssl/src/ssl.c`
- CWE / familia: `CWE-125` / `buffer-overflow`
- Log de ejecucion: `results/logs/codeql_smoke_wolfssl_CVE-2022-42905_real.log`
- SARIF:
  - `results/raw/codeql/wolfssl/CVE-2022-42905/V.sarif`
  - `results/raw/codeql/wolfssl/CVE-2022-42905/S.sarif`
- DB snapshots:
  - `results/raw/codeql/wolfssl/CVE-2022-42905/db_V/src.zip`
  - `results/raw/codeql/wolfssl/CVE-2022-42905/db_S/src.zip`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 16:40:17,608`
- Fin V DB: `2026-04-10 16:57:54,198`
- Fin V analyze: `2026-04-10 17:04:26,330` (`377.72s`)
- Fin S DB: `2026-04-10 17:42:42,519`
- Fin S analyze: `2026-04-10 17:54:10,629` (`658.01s`)
- Fin instancia: `2026-04-10 17:54:16,552`

## Resumen cuantitativo V/S

- V total findings: `38`
- S total findings: `31`
- Reglas unicas V/S: `11 / 9`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `29`
- FP_S: `22`
- INTERSECTION: `13`
- ONLY_V: `16`
- ONLY_S: `9`
- Persistencia: `0.4483`

## Analisis en fichero afectado

- Findings en `wolfssl/src/ssl.c`:
  - V: `0`
  - S: `0`
- Reglas en fichero afectado (V): `[]`
- Reglas en fichero afectado (S): `[]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `affected_file_not_found_in_src_zip`
- Rangos parcheados (lado S): `[]`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0`
  - ONLY_S: `0`

## Veredicto objetivo

- Veredicto: `inconcluso-por-ausencia-de-fichero-afectado-en-srczip`
- Justificacion: No se pudo reconstruir la zona parcheada porque `wolfssl/src/ssl.c` no aparece en `src.zip` para esta instancia.

## Notas

- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
