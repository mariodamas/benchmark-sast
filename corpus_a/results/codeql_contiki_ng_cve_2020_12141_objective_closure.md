# Cierre Objetivo CodeQL - Contiki-NG CVE-2020-12141

Fecha: 2026-04-13
Herramienta: CodeQL 2.25.1
Proyecto: contiki-ng
Instancia: CONTIKI-CVE-2020-12141

## Alcance

Analisis objetivo V/S para `CVE-2020-12141` usando artefactos locales del benchmark.

## Entradas

- Ground truth: `corpus/contiki-ng/ground_truth.yaml`
- Fichero afectado: `os/net/app-layer/snmp/snmp-ber.c`
- Log de ejecucion: `results/raw/codeql/logs/contiki-ng-rerun3.log`
- SARIF:
  - `results/raw/codeql/contiki-ng/CVE-2020-12141/V.sarif`
  - `results/raw/codeql/contiki-ng/CVE-2020-12141/S.sarif`
- DB snapshots:
  - `results/raw/codeql/contiki-ng/CVE-2020-12141/db_V/src.zip`
  - `results/raw/codeql/contiki-ng/CVE-2020-12141/db_S/src.zip`

## Estado de ejecucion

- V DB create: OK
- V analyze: OK
- S DB create: OK
- S analyze: OK

## Resumen cuantitativo V/S

- V total findings: `74`
- S total findings: `74`
- Reglas unicas V/S: `6 / 6`

Diff por fingerprint (`ruleId + file + line_bucket`):
- `ONLY_V`: `0`
- `ONLY_S`: `0`
- `INTERSECTION`: `42`

## Analisis en fichero afectado

En `os/net/app-layer/snmp/snmp-ber.c`:
- V findings: `0`
- S findings: `0`
- Reglas observadas: `[]`

## Correlacion con zona parcheada

- Estado reconstruccion parche: `affected_file_not_found_in_src_zip`
- Findings cerca del parche (`+/-20`):
  - V: `0`
  - S: `0`
  - ONLY_V: `0`
  - ONLY_S: `0`

## Veredicto objetivo

- Clasificacion benchmark (instancia): `FN`
- Justificacion: no hay hallazgos en el fichero afectado ni evidencia de senal que aparezca en V y desaparezca en S.

## Conclusiones operativas

- La ejecucion tecnica fue correcta (DB y SARIF en V/S).
- Bajo el criterio del benchmark, CodeQL no detecta esta vulnerabilidad en esta corrida.
