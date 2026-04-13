# Cierre Objetivo CodeQL - wolfSSL CVE-2021-38597

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: wolfSSL
Instancia: WOLFSSL-CVE-2021-38597

## Alcance

Analisis objetivo V/S para `CVE-2021-38597` usando SARIF y `src.zip` del benchmark.

## Entradas

- Ground truth: `corpus/wolfssl/ground_truth.yaml`
- Fichero afectado: `wolfcrypt/src/asn.c`
- CWE / familia: `CWE-125` / `buffer-overflow`
- Log de ejecucion: `results/logs/codeql_smoke_wolfssl_CVE-2021-38597_real.log`
- SARIF:
  - `results/raw/codeql/wolfssl/CVE-2021-38597/V.sarif`
  - `results/raw/codeql/wolfssl/CVE-2021-38597/S.sarif`
- DB snapshots:
  - `results/raw/codeql/wolfssl/CVE-2021-38597/db_V/src.zip`
  - `results/raw/codeql/wolfssl/CVE-2021-38597/db_S/src.zip`

## Estado de ejecucion

- Inicio instancia: `2026-04-10 17:02:45,034`
- Fin V DB: `2026-04-10 17:28:12,594`
- Fin V analyze: `2026-04-10 17:38:39,973` (`599.38s`)
- Fin S DB: `2026-04-10 18:05:37,987`
- Fin S analyze: `2026-04-10 18:13:26,371` (`447.87s`)
- Fin instancia: `2026-04-10 18:13:27,838`

## Resumen cuantitativo V/S

- V total findings: `30`
- S total findings: `32`
- Reglas unicas V/S: `9 / 9`

Diff por fingerprint (`ruleId + file + line_bucket`):
- FP_V: `22`
- FP_S: `25`
- INTERSECTION: `9`
- ONLY_V: `13`
- ONLY_S: `16`
- Persistencia: `0.4091`

## Analisis en fichero afectado

- Findings en `wolfcrypt/src/asn.c`:
  - V: `1`
  - S: `1`
- Reglas en fichero afectado (V): `["cpp/potentially-dangerous-function"]`
- Reglas en fichero afectado (S): `["cpp/potentially-dangerous-function"]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `ok`
- Fichero encontrado en `src.zip`:
  - V: `.../repos/wolfssl_w2/wolfcrypt/src/asn.c`
  - S: `.../repos/wolfssl_w2/wolfcrypt/src/asn.c`
- Rangos parcheados detectados (lado S, muestra):
  - `[3-3], [117-120], [391-391], [421-421], [505-505], [535-535], [563-576], [593-606], [653-670], [693-710], ...`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `1`
  - ONLY_S: `1`

## Veredicto objetivo

- Veredicto: `inconcluso-sin-desaparicion-clara`
- Justificacion: Hay senal en el fichero afectado, pero persiste en V y S y no cae en la ventana del parche; no hay evidencia robusta de desaparicion especifica del defecto.

## Notas

- En el log aparecen bloques `ERROR STDERR` durante la fase de build por comandos de preparacion/autotools, pero la corrida final es valida (se crearon DB y SARIF de V y S).
- Si existe `V.error.json`, corresponde a intentos previos y no invalida esta corrida final completada.
- Metodo reproducible: V/S SARIF + `affected_file` + diff V/S de `src.zip` + ventana de lineas.
