# Reporte Tecnico CodeQL - FreeRTOS CVE-2018-16522

Fecha: 2026-04-13  
Herramienta: CodeQL 2.25.1  
Proyecto: freertos (aws/amazon-freertos legacy)  
Instancia GT: FREERTOS-CVE-2018-16522  
Familia GT: buffer-overflow (CWE GT: CWE-824)

## 1) Objetivo de evaluacion

Validar, con evidencia de artefactos, si CodeQL genera una alerta en V que desaparece en S para la instancia CVE-2018-16522.

## 2) Evidencia usada

- Ground truth: corpus/freertos/ground_truth.yaml
- Affected file GT: lib/FreeRTOS-Plus-TCP/source/FreeRTOS_Sockets.c
- SARIF V: results/raw/codeql/freertos/CVE-2018-16522/V.sarif
- SARIF S: results/raw/codeql/freertos/CVE-2018-16522/S.sarif
- Build trace V: results/raw/codeql/freertos/CVE-2018-16522/db_V/log/build-tracer.log
- Fuente extraida V/S (desde src.zip):
  - results/_tmp_freertos_src/cve22_V/tmp/repos/amazon-freertos/lib/FreeRTOS-Plus-TCP/source/FreeRTOS_Sockets.c
  - results/_tmp_freertos_src/cve22_S/tmp/repos/amazon-freertos/lib/FreeRTOS-Plus-TCP/source/FreeRTOS_Sockets.c

## 3) Verificaciones objetivas

### 3.1 Ejecucion tecnica

- DB create y analyze completados en V y S (hay V.sarif/S.sarif y V.meta.json/S.meta.json).

### 3.2 Senal de deteccion

- V.sarif contiene `"results": []`.
- S.sarif contiene `"results": []`.
- No hay alerts en V ni en S, ni globales ni en el fichero afectado.

### 3.3 Cobertura de queries relevante

- En V.sarif esta cargada la query `cpp/uninitialized-local` (familia compatible con CWE-824/uso de variable/puntero no inicializado).
- No existe evidencia de que falte la familia uninitialized en esta corrida.

### 3.4 Cobertura de compilacion y extraccion

- El build-tracer confirma extraccion de:
  - lib/FreeRTOS-Plus-TCP/source/FreeRTOS_Sockets.c
  - lib/FreeRTOS-Plus-TCP/source/FreeRTOS_TCP_WIN.c
- Por tanto, el TU del fichero afectado segun GT si fue trazado y analizado.

## 4) Evaluacion tecnica (senior review)

Hallazgo principal: no hay deteccion pese a que la familia de query esperada (`cpp/uninitialized-local`) esta presente y el fichero afectado fue extraido.

Interpretacion mas probable:
- Caso de miss semantico/contextual de CodeQL para esta instancia concreta en este setup de build reducido (2 TU).
- Riesgo de validez adicional: el nombre funcional citado en la narrativa publica (SOCKETS_SetSockOpt) no aparece literalmente en el snapshot analizado; en el codigo aparece `FreeRTOS_setsockopt`.

## 5) Veredicto benchmark

- Clasificacion de instancia: FN
- Confianza del veredicto: media-alta

Razon:
- El criterio V/S no observa ninguna alerta en V.
- Hay cobertura de query/fichero suficiente para sostener que no fue un fallo trivial de ejecucion.

## 6) Riesgos y acciones recomendadas

- Riesgo metodologico moderado: compilacion minimalista (2 TU) puede reducir precision en flujos interprocedurales.
- Recomendado para cierre final del benchmark:
  1. Repetir esta instancia con build mas completo del modulo FreeRTOS-Plus-TCP.
  2. Mantener este resultado como FN en la tabla principal, con nota de validez sobre contexto de build.
