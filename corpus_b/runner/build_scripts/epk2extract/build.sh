#!/bin/bash
# =============================================================================
# build.sh — openlgtv/epk2extract
# Compatible con:
#   codeql database create --command="bash ./build.sh" ...
#   cov-build --dir cov_dir bash ./build.sh
#
# Dependencias:
#   apt-get install -y cmake gcc make libssl-dev zlib1g-dev libarchive-dev
#
# Target: host build (herramienta de extracción de firmware, funciona en host)
#   epk2extract es una herramienta de línea de comandos para extraer firmware
#   de TVs LG. No requiere hardware embebido.
#
# Variables de entorno requeridas:
#   REPO_PATH — ruta absoluta al repositorio clonado de epk2extract
#
# Ficheros clave compilados (contienen los defectos del benchmark):
#   src/stream/tsfile.c  (EPK2-DEFECT-001, EPK2-DEFECT-002)
#   include/common.h     (EPK2-DEFECT-003, compilado a través de main.c)
#   src/pkg.c            (EPK2-DEFECT-004, pendiente verificación)
# =============================================================================

set -euo pipefail

: "${REPO_PATH:?ERROR: REPO_PATH no definido. Exporta la ruta al repo de epk2extract.}"

cd "$REPO_PATH"

echo "[build.sh] epk2extract host build — $(pwd)"
echo "[build.sh] Commit: $(git rev-parse HEAD)"

# Limpiar build anterior
rm -rf build_benchmark

mkdir -p build_benchmark
cd build_benchmark

cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-O0 -g" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    2>&1

make -j"$(nproc)" 2>&1

echo "[build.sh] epk2extract host build completado."
