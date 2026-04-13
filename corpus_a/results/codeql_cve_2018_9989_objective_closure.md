# Cierre Objetivo CodeQL - CVE-2018-9989

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: mbedTLS
Instancia: MBEDTLS-CVE-2018-9989

## Alcance

Analisis objetivo V/S para `CVE-2018-9989` usando artefactos locales del benchmark.

## Entradas

- Ground truth: `corpus/mbedtls/ground_truth.yaml`
- Fichero afectado: `library/ssl_cli.c`
- CWE / familia: `CWE-125` / `buffer-overflow`
- Log de ejecucion: `results/logs/codeql_smoke_CVE-2018-9989_real.log`
- SARIF:
  - `results/raw/codeql/mbedtls/CVE-2018-9989/V.sarif`
  - `results/raw/codeql/mbedtls/CVE-2018-9989/S.sarif`
- DB snapshots:
  - `results/raw/codeql/mbedtls/CVE-2018-9989/db_V/src.zip`
  - `results/raw/codeql/mbedtls/CVE-2018-9989/db_S/src.zip`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 12:16:04,064`
- Fin V DB: `2026-04-10 12:20:59,837`
- Fin V analyze: `2026-04-10 12:32:54,509` (`710.0s`)
- Fin S DB: `2026-04-10 12:37:14,666`
- Fin S analyze: `2026-04-10 12:44:34,802` (`440.1s`)

## Resumen cuantitativo V/S

- V total findings: `135`
- S total findings: `138`
- Reglas unicas V/S: `11 / 11`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `104`
- FP_S: `107`
- INTERSECTION: `98`
- ONLY_V: `6`
- ONLY_S: `9`
- Persistencia: `0.9423`

## Analisis en fichero afectado

- Findings en `library/ssl_cli.c`:
  - V: `1`
  - S: `1`
- Reglas en fichero afectado (V): `[("cpp/use-after-free", 1)]`
- Reglas en fichero afectado (S): `[("cpp/use-after-free", 1)]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `ok`
- Rangos parcheados (lado S): `[(905, 906), (914, 914), (933, 933), (2061, 2066), (2070, 2070), (2488, 2495), (2499, 2499)]`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0 []`
  - ONLY_S: `0 []`

## Veredicto objetivo

- Veredicto: `FN`
- Justificacion: No hay findings en la zona del parche ni en V ni en S.

## Notas

- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
- Informe orientado a clasificacion tecnica del benchmark (TP/FP/FN por instancia).
