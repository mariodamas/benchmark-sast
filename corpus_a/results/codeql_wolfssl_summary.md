# Resumen Ejecutivo - CodeQL en wolfSSL

Fecha: 2026-04-10
Herramienta: CodeQL 2.25.1
Corpus: `corpus/wolfssl/ground_truth.yaml`

## Alcance

Resumen consolidado de 5 ejecuciones con cierre objetivo V/S en wolfSSL.

Informes fuente:
- `results/codeql_wolfssl_cve_2022_34293_objective_closure.md`
- `results/codeql_wolfssl_cve_2023_3724_objective_closure.md`
- `results/codeql_wolfssl_cve_2021_38597_objective_closure.md`
- `results/codeql_wolfssl_cve_2022_42905_objective_closure.md`
- `results/codeql_wolfssl_cve_2021_3336_objective_closure.md`

## Estado Por CVE

| CVE | Fichero afectado | Resultado objetivo |
|---|---|---|
| CVE-2022-34293 | `wolfcrypt/src/pkcs7.c` | `FN` |
| CVE-2023-3724 | `src/tls13.c` | `FN` |
| CVE-2021-38597 | `wolfcrypt/src/asn.c` | `inconcluso-sin-desaparicion-clara` |
| CVE-2022-42905 | `wolfssl/src/ssl.c` | `inconcluso-por-ausencia-de-fichero-afectado-en-srczip` |
| CVE-2021-3336 | `src/tls13.c` | `FN` |

## Lectura Global

- Instancias con cierre objetivo: `5`
- `TP` confirmados: `0`
- `FN`: `3`
- `Inconclusas`: `2`

Interpretacion:
- En la muestra actual de wolfSSL no hay evidencia de deteccion especifica TP bajo criterio V/S estricto por zona parcheada.
- El patron dominante es ausencia de senal en `affected_file`/zona parcheada o senal persistente sin desaparicion clara entre V y S.

## Metricas Consolidadas

- Findings totales V acumulados: `165`
- Findings totales S acumulados: `162`
- Persistencia media (fingerprint `ruleId + file + line_bucket`): `0.4801`

Detalle de persistencia por CVE:
- CVE-2022-34293: `0.5714`
- CVE-2023-3724: `0.3810`
- CVE-2021-38597: `0.4091`
- CVE-2022-42905: `0.4483`
- CVE-2021-3336: `0.5909`

## Riesgos Metodologicos Observados

- En algunos casos aparecen `V.error.json`/`S.error.json` residuales de intentos previos; la validez de corrida se confirma con `V.sarif`, `S.sarif`, `V.meta.json`, `S.meta.json` y timestamps coherentes.
- `CVE-2022-42905` queda inconclusa porque el `affected_file` del ground truth no aparece en `src.zip`, impidiendo reconstruir zona parcheada.
- Bloques `ERROR STDERR` de autotools pueden coexistir con corrida final valida cuando DB y SARIF se generan correctamente.

## Conclusion

Con las 5 CVEs evaluadas en wolfSSL, CodeQL no muestra TP claros bajo el criterio objetivo aplicado. El resultado agregado es `FN` o `inconcluso`, por lo que conviene ampliar la muestra y mantener el mismo metodo de correlacion por `affected_file` y ventana de parche para comparaciones robustas entre herramientas y corpus.
