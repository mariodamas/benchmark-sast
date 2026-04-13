# Resumen Ejecutivo - CodeQL en mbedTLS

Fecha: 2026-04-10  
Herramienta: CodeQL 2.25.1  
Corpus: `corpus/mbedtls/ground_truth.yaml`

## Alcance

Resumen consolidado de ejecuciones y cierres objetivos V/S ya documentados para mbedTLS.

Informes fuente:
- `results/codeql_cve_2018_9988_objective_closure.md`
- `results/codeql_cve_2018_9989_objective_closure.md`
- `results/codeql_cve_2020_36475_objective_closure.md`
- `results/codeql_cve_2021_44732_objective_closure.md`
- `results/codeql_cve_2024_28755_objective_closure.md`

## Estado Por CVE

| CVE | Fichero afectado | Resultado objetivo |
|---|---|---|
| CVE-2018-9988 | `library/ssl_cli.c` | `FN` |
| CVE-2018-9989 | `library/ssl_cli.c` | `FN` |
| CVE-2020-36475 | `library/mps_reader.c` | `inconcluso-por-ausencia-de-fichero-afectado-en-srczip` |
| CVE-2021-44732 | `library/ssl_srv.c` | `FN` |
| CVE-2024-28755 | `library/bignum.c` | `no-TP` (senal persistente V/S; clasificado como `FP-persistente`/`inconcluso-sin-desaparicion`) |

## Lectura Global

- Instancias con cierre objetivo: `5`
- `TP` confirmados: `0`
- `FN`: `3`
- `Inconclusas/no-TP`: `2`

Interpretacion:
- En esta muestra, CodeQL genera senal amplia, pero no evidencia desaparicion clara en las zonas parcheadas para confirmar deteccion especifica de las CVEs evaluadas.
- La mayor parte de findings persisten entre V y S, lo que reduce capacidad discriminativa por instancia bajo criterio V/S estricto.

## Metricas Consolidadas (instancias con diff completo)

Para `CVE-2018-9988`, `CVE-2018-9989`, `CVE-2020-36475`, `CVE-2021-44732`:

- Findings totales V acumulados: `746`
- Findings totales S acumulados: `761`
- Persistencia media (fingerprint `ruleId + file + line_bucket`): `0.8876`

Detalle de persistencia por CVE:
- CVE-2018-9988: `0.9423`
- CVE-2018-9989: `0.9423`
- CVE-2020-36475: `0.9259`
- CVE-2021-44732: `0.7399`

## Hallazgos Operativos

- Ejecutar una CVE en un repo dedicado (`repos/mbedtls_<cve>`) mejora estabilidad frente a un repo compartido, especialmente en WSL sobre `/mnt/c`.
- Pueden quedar `V.error.json`/`S.error.json` de intentos previos aunque la corrida final sea valida; para cierre usar `V.sarif`, `S.sarif`, `V.meta.json`, `S.meta.json` y timestamps.
- Cuando `affected_file` no aparece en `src.zip`, el cierre debe marcarse como inconcluso para evitar sobreinterpretacion.

## Conclusion

Con la evidencia actual en mbedTLS, CodeQL no ha mostrado `TP` claros en las 5 instancias evaluadas bajo criterio objetivo de benchmark. El comportamiento dominante es `FN` o senal persistente/inconclusa, por lo que conviene ampliar muestra y mantener validacion estricta por zona parcheada antes de inferir efectividad por CVE.
