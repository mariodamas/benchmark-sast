# Cierre Objetivo CodeQL - wolfSSL CVE-2022-34293

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: wolfSSL
Instancia: WOLFSSL-CVE-2022-34293

## Alcance

Analisis objetivo V/S para `CVE-2022-34293` usando SARIF y `src.zip` del benchmark.

## Entradas

- Ground truth: `corpus/wolfssl/ground_truth.yaml`
- Fichero afectado: `wolfcrypt/src/pkcs7.c`
- Log de ejecucion: `results/logs/codeql_smoke_wolfssl_CVE-2022-34293_real.log`
- SARIF:
  - `results/raw/codeql/wolfssl/CVE-2022-34293/V.sarif`
  - `results/raw/codeql/wolfssl/CVE-2022-34293/S.sarif`
- DB snapshots:
  - `results/raw/codeql/wolfssl/CVE-2022-34293/db_V/src.zip`
  - `results/raw/codeql/wolfssl/CVE-2022-34293/db_S/src.zip`
- Metadatos:
  - `results/raw/codeql/wolfssl/CVE-2022-34293/V.meta.json`
  - `results/raw/codeql/wolfssl/CVE-2022-34293/S.meta.json`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 16:10:16,239`
- Fin V DB: `2026-04-10 16:18:28,789`
- Fin V analyze: `2026-04-10 16:21:45,422` (`189.13s`)
- Fin S DB: `2026-04-10 16:29:52,303`
- Fin S analyze: `2026-04-10 16:33:12,736` (`193.1s`)
- Fin instancia: `2026-04-10 16:33:13,824`

## Resumen cuantitativo V/S

- V total findings: `37`
- S total findings: `37`
- Reglas unicas V/S: `10 / 10`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `28`
- FP_S: `28`
- INTERSECTION: `16`
- ONLY_V: `12`
- ONLY_S: `12`
- Persistencia: `0.5714`

## Analisis en fichero afectado

- Findings en `wolfcrypt/src/pkcs7.c`:
  - V: `0`
  - S: `0`
- Reglas en fichero afectado (V): `[]`
- Reglas en fichero afectado (S): `[]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `ok`
- Fichero encontrado en `src.zip`:
  - V: `.../repos/wolfssl_cve_2022_34293/wolfcrypt/src/pkcs7.c`
  - S: `.../repos/wolfssl_cve_2022_34293/wolfcrypt/src/pkcs7.c`
- Rangos parcheados detectados (lado S, muestra):
  - `[363-363], [1768-1768], [1775-1775], [2621-2625], [4418-4418], [6432-6433], [6437-6437], [6441-6441], [6443-6443], [6446-6449], ...`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0`
  - ONLY_S: `0`

## Veredicto objetivo

- Veredicto: `FN`
- Justificacion: CodeQL no reporta hallazgos en el fichero afectado ni en ventana cercana a las lineas modificadas del fix, por lo que no hay evidencia de deteccion especifica de la vulnerabilidad bajo criterio V/S del benchmark.

## Notas

- `V.error.json` y `S.error.json` en esta carpeta provienen del intento previo fallido (antes del ajuste del runner para build autoconf). La corrida valida es la registrada en este informe con SARIF y metadatos de `16:10-16:33`.
- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
