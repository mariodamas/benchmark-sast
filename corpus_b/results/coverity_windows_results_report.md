# Informe de resultados Coverity en proyectos Windows-friendly

Fecha: 2026-04-16

## 1. Alcance de esta ejecución

Se documentan resultados obtenidos con el pipeline Coverity nativo en Windows (Opcion B) para:

- raylib
- mbed_os

Estado parcial adicional:

- epk2extract (solo artefacto intermedio de una instancia, sin V.json ni S.json finales)

## 2. Entorno y pipeline

- Runner: corpus_b/runner/run_coverity_windows.py
- Config de build Windows: corpus_b/runner/build_scripts_windows/build_commands_windows.json
- Motor: Coverity Static Analysis 2025.9.0 (Windows)
- Repos Windows: C:/Users/EXTmdamas/repos_b_windows

## 3. Resumen ejecutivo

| Proyecto | Instancias evaluables | V.json | S.json | Resultado de clasificacion |
|---|---:|---:|---:|---|
| raylib | 6 | 6 | 6 | FN = 6 |
| mbed_os | 4 | 4 | 4 | FN = 4 |
| Total | 10 | 10 | 10 | FN = 10 |

Notas:

- Los artefactos V.json y S.json existen para todas las instancias de raylib y mbed_os.
- En ambos proyectos, la clasificacion estricta del runner no encontro coincidencias en archivo afectado + checker esperado, por eso quedan en FN.

## 4. Detalle por proyecto

### 4.1 raylib

Instancias:

- RAYLIB-DEFECT-001: FN
- RAYLIB-DEFECT-002: FN
- RAYLIB-DEFECT-003: FN
- RAYLIB-DEFECT-004: FN
- RAYLIB-DEFECT-005: FN
- RAYLIB-DEFECT-006: FN

Cobertura de artefactos:

- V.json: 6/6
- S.json: 6/6

### 4.2 mbed_os

Instancias:

- MBEDOS-DEFECT-001: FN
- MBEDOS-DEFECT-002: FN
- MBEDOS-DEFECT-003: FN
- MBEDOS-DEFECT-004: FN

Cobertura de artefactos:

- V.json: 4/4
- S.json: 4/4

## 5. Hallazgos tecnicos y posibles motivos de fallo

1. El pipeline de captura y analisis funciona

- Se verifico emision de unidades de compilacion y ejecucion completa de cov-analyze/cov-format-errors en mbed_os.
- En raylib tambien se obtuvieron V.json y S.json para todas las instancias.

2. El problema actual esta en alineacion de deteccion, no en generacion de artefactos

- La logica de clasificacion exige match de issue en archivo afectado y, ademas, checker esperado por familia CWE.
- Aunque Coverity puede reportar defectos en la TU analizada, si no caen en el archivo afectado esperado, la instancia clasifica como FN.

3. Limitacion metodologica relevante para mbed_os

- Para estabilizar el build Windows y asegurar captura, se usa compilacion controlada de una TU representativa.
- Eso mejora robustez del pipeline, pero puede reducir cobertura directa sobre los otros archivos afectados de ground truth.

## 6. Artefactos de salida relevantes

- Log de ejecucion Windows (ultima corrida completa mbed_os):
  corpus_b/results/coverity_windows_run_log.json
- Clasificaciones de ultima corrida con --classify (mbed_os):
  corpus_b/results/coverity_classifications_windows.json
- Resultados por instancia:
  corpus_b/results/coverity/raylib/
  corpus_b/results/coverity/mbed_os/

## 7. Estado final

- Proyecto raylib: completado en Windows, con V/S para todas las instancias.
- Proyecto mbed_os: completado en Windows, con V/S para todas las instancias.
- Proyecto epk2extract: no completado en esta fase Windows-friendly (sin V/S finales).
