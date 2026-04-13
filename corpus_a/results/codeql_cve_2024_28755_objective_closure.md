# Cierre Objetivo CodeQL - CVE-2024-28755

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Proyecto: mbedTLS
Instancia: MBEDTLS-CVE-2024-28755

## Alcance

Este documento registra un cierre objetivo V/S para `CVE-2024-28755` usando solo artefactos locales generados por la ejecucion del benchmark.

## Entradas

- Ground truth: `corpus/mbedtls/ground_truth.yaml`
- Fichero afectado: `library/bignum.c`
- Salidas SARIF:
	- `results/raw/codeql/mbedtls/CVE-2024-28755/V.sarif`
	- `results/raw/codeql/mbedtls/CVE-2024-28755/S.sarif`
- Snapshots locales del codigo en las DB de CodeQL:
	- `results/raw/codeql/mbedtls/CVE-2024-28755/db_V/src.zip`
	- `results/raw/codeql/mbedtls/CVE-2024-28755/db_S/src.zip`

## Metodo (Objetivo)

1. Se extrajo `tmp/repos/mbedtls/library/bignum.c` desde `db_V/src.zip` y `db_S/src.zip`.
2. Se reconstruyeron las regiones parcheadas comparando snapshots V vs S.
3. Se filtraron findings SARIF por:
	 - fichero afectado (`library/bignum.c`)
	 - familia de reglas coherente con comportamiento integer/arithmetic:
		 - `cpp/integer-overflow-tainted`
		 - `cpp/tainted-arithmetic`
		 - `cpp/uncontrolled-arithmetic`
4. Se compararon findings cercanos a zonas parcheadas con ventana de `+/-20` lineas.
5. Se uso fingerprinting grueso (`ruleId + line_bucket`) para medir persistencia y desaparicion.

## Resumen de Evidencia

- Findings candidatos en el fichero afectado:
	- `V`: 7
	- `S`: 7
- Findings candidatos cerca de regiones parcheadas (`+/-20`):
	- `V`: 6
	- `S`: 6
- Deltas cerca del parche:
	- `ONLY_V`: 2
	- `ONLY_S`: 2

Los deltas cerca del parche corresponden a desplazamientos de bucket (por ejemplo bucket `41` vs `42`) y no muestran un patron claro de desaparicion solo en vulnerable.

## Veredicto

Clasificacion objetiva para esta ejecucion:

- `TP`: Sin evidencia clara
- `FN`: No soportado por la evidencia actual
- `Mejor ajuste`: Senal persistente entre V y S (no-TP para esta instancia en esta ejecucion)

Etiqueta practica de benchmark:

- `FP-persistente` (o `inconcluso-sin-desaparicion` si prefieres una redaccion mas estricta)

## Notas

- Este cierre se completo en modo offline (sin depender de acceso remoto a git), usando solo artefactos del benchmark.
- El enfoque es reproducible para CVEs adicionales reutilizando `db_V/src.zip`, `db_S/src.zip` y `V/S.sarif`.

