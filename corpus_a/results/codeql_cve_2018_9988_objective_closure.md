# Cierre Objetivo CodeQL - CVE-2018-9988

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: mbedTLS
Instancia: MBEDTLS-CVE-2018-9988

## Alcance

Este documento registra el cierre objetivo V/S para `CVE-2018-9988` usando artefactos locales del benchmark.

## Entradas

- Ground truth: `corpus/mbedtls/ground_truth.yaml`
- Fichero afectado: `library/ssl_cli.c`
- Datos de ejecucion:
  - `results/logs/codeql_smoke_CVE-2018-9988_real.log`
- SARIF:
  - `results/raw/codeql/mbedtls/CVE-2018-9988/V.sarif`
  - `results/raw/codeql/mbedtls/CVE-2018-9988/S.sarif`
- Snapshots de codigo:
  - `results/raw/codeql/mbedtls/CVE-2018-9988/db_V/src.zip`
  - `results/raw/codeql/mbedtls/CVE-2018-9988/db_S/src.zip`

## Tiempos de ejecucion

- Inicio instancia: `11:30:39`
- Fin instancia: `11:40:19`
- Duracion total aproximada: `9m 40s`

Detalle:
- V DB create: `11:30:59` -> `11:32:58` (~1m 59s)
- V analyze: `163.3s` (~2m 43s)
- S DB create: `11:35:47` -> `11:37:31` (~1m 44s)
- S analyze: `161.3s` (~2m 41s)

## Resumen cuantitativo V/S

- V total findings: `135`
- S total findings: `138`
- Reglas unicas en ambos: `11`

Diff por fingerprint (`ruleId + file + line_bucket`):
- `FP_V`: `104`
- `FP_S`: `107`
- `INTERSECTION`: `98`
- `ONLY_V`: `6`
- `ONLY_S`: `9`
- Persistencia: `0.9423` (~94.23%)

## Analisis en fichero afectado

En `library/ssl_cli.c`:
- V findings: `1`
- S findings: `1`
- Regla observada en ambos: `cpp/use-after-free`
- Lineas: `1426` (V) y `1427` (S)

Nota: el GT de la instancia es `CWE-125` (buffer-overflow/OOB read), pero la senal de CodeQL en este fichero es `use-after-free` y persiste en V y S.

## Correlacion con zonas parcheadas (objetivo)

Regiones parcheadas reconstruidas desde `db_V/src.zip` vs `db_S/src.zip` en `ssl_cli.c`:
- `(905-906), (914), (933), (2061-2066), (2070), (2488-2495), (2499)`

Findings en ventana `+/-20` lineas alrededor de regiones parcheadas:
- V: `0`
- S: `0`
- `ONLY_V`: `0`
- `ONLY_S`: `0`

## Veredicto

Clasificacion objetiva para esta ejecucion:

- `TP`: No hay evidencia
- `FN`: Compatible con la evidencia disponible
- `Mejor ajuste`: `FN` para esta instancia (CodeQL no muestra una senal candidata en la zona del parche que desaparezca en S)

## Conclusiones operativas

- La ejecucion tecnica fue correcta (DB y SARIF generados para V y S).
- La evidencia no soporta deteccion especifica del defecto de `CVE-2018-9988`.
- La senal encontrada en `ssl_cli.c` no es de la familia esperada y ademas persiste tras el fix.
