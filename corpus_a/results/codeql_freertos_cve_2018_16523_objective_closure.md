# Reporte Tecnico CodeQL - FreeRTOS CVE-2018-16523

Fecha: 2026-04-13  
Herramienta: CodeQL 2.25.1  
Proyecto: freertos (aws/amazon-freertos legacy)  
Instancia GT: FREERTOS-CVE-2018-16523  
Familia GT: integer-overflow (CWE GT: CWE-369)

## 1) Objetivo de evaluacion

Validar, con evidencia tecnica, si CodeQL detecta en V una alerta relevante que desaparece en S para CVE-2018-16523.

## 2) Evidencia usada

- Ground truth: corpus/freertos/ground_truth.yaml
- Affected file GT: lib/FreeRTOS-Plus-TCP/source/FreeRTOS_TCP_WIN.c
- SARIF V: results/raw/codeql/freertos/CVE-2018-16523/V.sarif
- SARIF S: results/raw/codeql/freertos/CVE-2018-16523/S.sarif
- Build trace V: results/raw/codeql/freertos/CVE-2018-16523/db_V/log/build-tracer.log
- Fuente extraida V/S (desde src.zip):
  - results/_tmp_freertos_src/cve23_V/tmp/repos/amazon-freertos/lib/FreeRTOS-Plus-TCP/source/FreeRTOS_TCP_WIN.c
  - results/_tmp_freertos_src/cve23_S/tmp/repos/amazon-freertos/lib/FreeRTOS-Plus-TCP/source/FreeRTOS_TCP_WIN.c

## 3) Verificaciones objetivas

### 3.1 Ejecucion tecnica

- DB create y analyze completados en V y S.
- El build-tracer confirma extraccion de `FreeRTOS_TCP_WIN.c` y `FreeRTOS_Sockets.c`.

### 3.2 Senal de deteccion

- V.sarif contiene `"results": []`.
- S.sarif contiene `"results": []`.
- No hay alerts en V ni en S.

### 3.3 Cobertura de query para CWE-369

- En la lista de reglas cargadas no aparece `cpp/division-by-zero`.
- Si aparece `cpp/uninitialized-local`, pero no es la familia principal esperada para una division por cero.

### 3.4 Coherencia V/S del fichero afectado

Comparacion directa V vs S del fichero GT `FreeRTOS_TCP_WIN.c`:
- Solo cambia la cabecera de version (`V2.0.6` -> `V2.0.7`).
- No se observan cambios funcionales en el cuerpo del archivo para esta pareja de commits.

Adicionalmente:
- El identificador funcional mencionado en la narrativa GT (`prvCheckOptions`) no aparece en los snapshots analizados.

## 4) Evaluacion tecnica (senior review)

Este caso no debe interpretarse como un FN puro de herramienta sin matices.

Resultado tecnico de la corrida:
- 0 findings V/S.

Pero hay dos riesgos metodologicos fuertes:
1. Falta de query explicita de division-by-zero en la suite usada (`security-extended`).
2. Desalineacion de trazabilidad CVE->fichero/parche en la pareja V/S actual (archivo casi inalterado y funcion esperada ausente).

## 5) Veredicto benchmark

- Clasificacion operativa actual (si se fuerza matriz TP/FP/FN): FN
- Confianza del veredicto: baja
- Estado recomendado para informe academico: INCONCLUSO METODOLOGICO hasta corregir trazabilidad del caso.

## 6) Riesgos y acciones recomendadas

1. Revisar la instancia GT CVE-2018-16523 (archivo afectado y pareja de commits) con evidencia de patch real.
2. Reejecutar con una suite que incluya explicitamente la query de division por cero (o pack equivalente).
3. No usar este punto para inferencias fuertes de recall hasta cerrar la trazabilidad.
