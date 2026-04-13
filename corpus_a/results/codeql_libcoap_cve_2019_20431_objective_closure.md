# Reporte Tecnico CodeQL - libcoap CVE-2019-20431

Fecha: 2026-04-13  
Herramienta: CodeQL 2.25.1  
Proyecto: libcoap  
Instancia GT: LIBCOAP-CVE-2019-20431  
Familia GT: null-deref (CWE GT: CWE-476)

## 1) Objetivo de evaluacion

Verificar con evidencia V/S si existe alerta en V que desaparece en S para CVE-2019-20431.

## 2) Evidencia usada

- Ground truth: corpus/libcoap/ground_truth.yaml
- Affected file GT: src/net.c
- SARIF V: results/raw/codeql/libcoap/CVE-2019-20431/V.sarif
- SARIF S: results/raw/codeql/libcoap/CVE-2019-20431/S.sarif
- Meta V/S:
  - results/raw/codeql/libcoap/CVE-2019-20431/V.meta.json
  - results/raw/codeql/libcoap/CVE-2019-20431/S.meta.json

## 3) Verificaciones objetivas

### 3.1 Ejecucion tecnica

- La instancia esta completa en V y S (hay DB, SARIF y meta en ambas versiones).
- Los marcadores de error antiguos ya no estan presentes para V/S.

### 3.2 Resumen cuantitativo V/S

- V total findings: 36
- S total findings: 36
- ONLY_V (ruleId + file + line_bucket): 0
- ONLY_S (ruleId + file + line_bucket): 0
- INTERSECTION: 36

### 3.3 Senal en fichero afectado GT

- V findings en src/net.c: 0
- S findings en src/net.c: 0
- ONLY_V en src/net.c: 0

### 3.4 Perfil de alertas observado

- Top reglas en V (igual en S):
  - cpp/integer-overflow-tainted: 17
  - cpp/tainted-arithmetic: 14
  - cpp/arithmetic-with-extreme-values: 2
  - cpp/non-constant-format: 1
  - cpp/incorrect-not-operator-usage: 1
  - cpp/potentially-dangerous-function: 1

Nota de cobertura:
- No se observa `cpp/dereferenced-value-may-be-null` en el conjunto de reglas cargadas de esta corrida.

## 4) Evaluacion tecnica (senior review)

La ejecucion de libcoap queda arreglada y estable a nivel de pipeline (V/S completos y reproducibles).

A nivel de deteccion de la instancia:
- No hay senal en el fichero afectado.
- No hay diferencia V->S en findings normalizados por bucket.
- Las alertas presentes son ruido estable entre versiones y no evidencian el fix del CVE.

## 5) Veredicto benchmark

- Clasificacion de instancia: FN
- Confianza del veredicto: media

Razon:
- No existe alerta candidata en V vinculada al objetivo GT que desaparezca en S.
- Ademas, la cobertura null-deref parece limitada en la suite efectiva usada en esta corrida.

## 6) Conclusiones operativas

1. El problema tecnico de ejecucion de libcoap queda resuelto (ya no esta inconcluso por fallo de infraestructura).
2. Para maximizar sensibilidad a CWE-476, conviene repetir con una suite/pack que incluya explicitamente query de null-deref fuerte.
