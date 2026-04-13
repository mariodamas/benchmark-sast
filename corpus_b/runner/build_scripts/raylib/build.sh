#!/bin/bash
# =============================================================================
# build.sh — raysan5/raylib
# Compatible con:
#   codeql database create --command="bash ./build.sh" ...
#   cov-build --dir cov_dir bash ./build.sh
#
# Dependencias (Ubuntu/Debian):
#   apt-get install -y cmake gcc g++ libgl1-mesa-dev libxi-dev \
#     libxcursor-dev libxrandr-dev libxinerama-dev libwayland-dev \
#     libxkbcommon-dev
#
# Target: Desktop (compilación en host, no requiere hardware)
#   Compila la librería completa incluyendo todos los módulos afectados.
#
# Variables de entorno requeridas:
#   REPO_PATH — ruta absoluta al repositorio clonado de raylib
#
# Ficheros clave compilados (contienen los defectos del benchmark):
#   src/rcore.c       (RAYLIB-DEFECT-001, RAYLIB-DEFECT-002)
#   src/external/jar_mod.h  compilado vía raudio.c (RAYLIB-DEFECT-003)
#   src/rmodels.c     (RAYLIB-DEFECT-004)
#   src/raudio.c      (RAYLIB-DEFECT-005)
#   src/rtextures.c   (RAYLIB-DEFECT-006)
# =============================================================================

set -euo pipefail

: "${REPO_PATH:?ERROR: REPO_PATH no definido. Exporta la ruta al repo de raylib.}"

cd "$REPO_PATH"

echo "[build.sh] raylib Desktop build — $(pwd)"
echo "[build.sh] Commit: $(git rev-parse HEAD)"

# Limpiar build anterior
rm -rf build_benchmark

mkdir -p build_benchmark
cd build_benchmark

cmake .. \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=Debug \
    -DPLATFORM=Desktop \
    -DCMAKE_C_FLAGS="-O0 -g" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    2>&1

make -j"$(nproc)" 2>&1

echo "[build.sh] raylib Desktop build completado."
echo "[build.sh] compile_commands.json disponible en: $(pwd)/compile_commands.json"
