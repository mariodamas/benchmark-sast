# Cierre Objetivo CodeQL - CVE-2020-36475

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: mbedTLS
Instancia: MBEDTLS-CVE-2020-36475

## Alcance

Analisis objetivo V/S para `CVE-2020-36475` usando artefactos locales del benchmark.

## Entradas

- Ground truth: `corpus/mbedtls/ground_truth.yaml`
- Fichero afectado: `library/mps_reader.c`
- CWE / familia: `CWE-125` / `buffer-overflow`
- Log de ejecucion: `results/logs/codeql_smoke_CVE-2020-36475_real.log`
- SARIF:
  - `results/raw/codeql/mbedtls/CVE-2020-36475/V.sarif`
  - `results/raw/codeql/mbedtls/CVE-2020-36475/S.sarif`
- DB snapshots:
  - `results/raw/codeql/mbedtls/CVE-2020-36475/db_V/src.zip`
  - `results/raw/codeql/mbedtls/CVE-2020-36475/db_S/src.zip`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 12:16:29,585`
- Fin V DB: `2026-04-10 12:22:55,439`
- Fin V analyze: `2026-04-10 12:35:07,046` (`730.7s`)
- Fin S DB: `2026-04-10 12:41:58,561`
- Fin S analyze: `2026-04-10 12:48:56,811` (`418.2s`)

## Resumen cuantitativo V/S

- V total findings: `239`
- S total findings: `237`
- Reglas unicas V/S: `11 / 11`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `135`
- FP_S: `133`
- INTERSECTION: `125`
- ONLY_V: `10`
- ONLY_S: `8`
- Persistencia: `0.9259`

## Analisis en fichero afectado

- Findings en `library/mps_reader.c`:
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
  - ONLY_V: `0 []`
  - ONLY_S: `0 []`

## Veredicto objetivo

- Veredicto: `inconcluso-por-ausencia-de-fichero-afectado-en-srczip`
- Justificacion: No se pudo reconstruir la zona parcheada porque el fichero afectado del ground truth no aparece en `src.zip`.

## Notas

- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
- Informe orientado a clasificacion tecnica del benchmark (TP/FP/FN por instancia).
