#!/bin/bash
# =============================================================================
# build.sh — apache/nuttx
# Compatible con:
#   codeql database create --command="bash ./build.sh" ...
#   cov-build --dir cov_dir bash ./build.sh
#
# Dependencias:
#   apt-get install -y gcc make kconfig-frontends genromfs gperf bison flex
#   pip install pyelftools
#
# Target: sim:nsh (simulador software, no requiere hardware embebido)
#   El simulador compila el RTOS completo para host x86/x64, incluyendo
#   todos los drivers y módulos relevantes para los defectos del benchmark.
#
# Variables de entorno requeridas:
#   REPO_PATH — ruta absoluta al repositorio clonado de apache/nuttx
#
# Ficheros clave compilados (contienen los defectos del benchmark):
#   sched/sched/sched_mergepending.c   (NUTTX-DEFECT-001)
#   sched/irq/irq_attach_thread.c      (NUTTX-DEFECT-002)
#   drivers/sensors/gnss_uorb.c        (NUTTX-DEFECT-003)
#   drivers/video/fb.c                 (NUTTX-DEFECT-004)
#   arch/xtensa/src/esp32/esp32_spi.c  (NUTTX-DEFECT-005, solo con ESP32 config)
# =============================================================================

set -euo pipefail

: "${REPO_PATH:?ERROR: REPO_PATH no definido. Exporta la ruta al repo de nuttx.}"

cd "$REPO_PATH"

echo "[build.sh] NuttX sim build — $(pwd)"
echo "[build.sh] Commit: $(git rev-parse HEAD)"

# Limpiar build anterior para forzar recompilación completa
# (necesario para que CodeQL y cov-build capturen todas las TUs)
make distclean 2>/dev/null || true

# Configurar para simulador (host)
./tools/configure.sh sim:nsh

# Compilar con todos los núcleos disponibles
# EXTRA_CFLAGS=-O0 desactiva optimizaciones para que CodeQL trace mejor el flujo
make -j"$(nproc)" EXTRA_CFLAGS="-O0 -g" 2>&1

echo "[build.sh] NuttX sim build completado."

# Nota para NUTTX-DEFECT-005 (arch/xtensa/esp32):
# El fichero esp32_spi.c requiere configuración ESP32 (no compilado con sim:nsh).
# Para incluirlo, usar una segunda pasada con config xtensa:esp32evb:
#   ./tools/configure.sh xtensa/esp32evb:nsh
#   make -j$(nproc) EXTRA_CFLAGS="-O0 -g" arch/xtensa/src/esp32/esp32_spi.c 2>&1
# Esto requiere el cross-compiler xtensa-esp32-elf-gcc.
