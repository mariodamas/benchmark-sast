# Cierre Objetivo CodeQL - wolfSSL CVE-2021-3336

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: wolfSSL
Instancia: WOLFSSL-CVE-2021-3336

## Alcance

Analisis objetivo V/S para `CVE-2021-3336` usando SARIF y `src.zip` del benchmark.

## Entradas

- Ground truth: `corpus/wolfssl/ground_truth.yaml`
- Fichero afectado: `src/tls13.c`
- CWE / familia: `CWE-122` / `buffer-overflow`
- Log de ejecucion: `results/logs/codeql_smoke_wolfssl_CVE-2021-3336_real.log`
- SARIF:
  - `results/raw/codeql/wolfssl/CVE-2021-3336/V.sarif`
  - `results/raw/codeql/wolfssl/CVE-2021-3336/S.sarif`
- DB snapshots:
  - `results/raw/codeql/wolfssl/CVE-2021-3336/db_V/src.zip`
  - `results/raw/codeql/wolfssl/CVE-2021-3336/db_S/src.zip`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 17:03:02,619`
- Fin V DB: `2026-04-10 17:28:57,524`
- Fin V analyze: `2026-04-10 17:39:08,492` (`584.33s`)
- Fin S DB: `2026-04-10 18:02:15,586`
- Fin S analyze: `2026-04-10 18:09:39,859` (`425.34s`)
- Fin instancia: `2026-04-10 18:09:42,054`

## Resumen cuantitativo V/S

- V total findings: `30`
- S total findings: `30`
- Reglas unicas V/S: `9 / 9`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `22`
- FP_S: `22`
- INTERSECTION: `13`
- ONLY_V: `9`
- ONLY_S: `9`
- Persistencia: `0.5909`

## Analisis en fichero afectado

- Findings en `src/tls13.c`:
  - V: `0`
  - S: `0`
- Reglas en fichero afectado (V): `[]`
- Reglas en fichero afectado (S): `[]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `ok`
- Fichero encontrado en `src.zip`:
  - V: `.../repos/wolfssl_w4/src/tls13.c`
  - S: `.../repos/wolfssl_w4/src/tls13.c`
- Rangos parcheados detectados (lado S, muestra):
  - `[32-33], [517-517], [690-690], [706-706], [724-821], [962-962], [965-974], [1331-1332], [1471-1487], [1500-1501], ...`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0`
  - ONLY_S: `0`

## Veredicto objetivo

- Veredicto: `FN`
- Justificacion: No hay findings en el fichero afectado ni en ventana cercana a las lineas parcheadas en V/S.

## Notas

- Aunque el log muestra bloques `ERROR STDERR` en preparacion autoconf, la corrida final es valida (DB y SARIF creados para V y S).
- Si aparecen `V.error.json`/`S.error.json`, corresponden a intentos previos o fallos transitorios de preparacion, no a la corrida final completa de esta instancia.
- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
