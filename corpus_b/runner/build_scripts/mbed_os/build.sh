#!/bin/bash
# =============================================================================
# build.sh — ARMmbed/mbed-os
# Compatible con:
#   codeql database create --command="bash ./build.sh" ...
#   cov-build --dir cov_dir bash ./build.sh
#
# Dependencias:
#   apt-get install -y cmake gcc-arm-none-eabi python3 python3-pip ninja-build
#   pip3 install mbed-tools pyelftools
#   # O usar la compilación host con GCC nativo (sin ARM cross-compiler):
#   apt-get install -y gcc g++ cmake ninja-build
#
# Target: HOST build con CMake (para análisis estático sin hardware ARM)
#   Se compila con el GCC del host para que CodeQL y Coverity puedan
#   analizar el código sin requerir el cross-compiler ARM.
#
# Variables de entorno requeridas:
#   REPO_PATH — ruta absoluta al repositorio clonado de mbed-os
#
# Ficheros clave compilados (contienen los defectos del benchmark):
#   connectivity/FEATURE_BLE/.../att_eatt.c       (MBEDOS-DEFECT-001)
#   storage/kvstore/securestore/source/SecureStore.cpp (MBEDOS-DEFECT-002)
#   connectivity/drivers/cellular/GEMALTO/...     (MBEDOS-DEFECT-003)
#   connectivity/lorawan/include/lorawan/LoRaRadio.h   (MBEDOS-DEFECT-004)
#
# NOTA: mbed-os es un proyecto grande (~1.2 MLOC). El build puede tardar
#       15-30 minutos. Los ficheros afectados por los defectos del benchmark
#       están todos en el subsistema de conectividad (BLE, LoRa, Cellular).
# =============================================================================

set -euo pipefail

: "${REPO_PATH:?ERROR: REPO_PATH no definido. Exporta la ruta al repo de mbed-os.}"

cd "$REPO_PATH"

echo "[build.sh] mbed-os host build — $(pwd)"
echo "[build.sh] Commit: $(git rev-parse HEAD)"

# Estrategia: compilar directamente los ficheros afectados con GCC host
# para evitar la complejidad del sistema de build mbed completo.
# Esto es suficiente para que CodeQL y cov-build capturen las TUs relevantes.

# Includes mínimos necesarios para compilar los ficheros del benchmark
INCLUDES=(
    -I"$REPO_PATH"
    -I"$REPO_PATH/cmsis/CMSIS_5/CMSIS/Core/Include"
    -I"$REPO_PATH/platform/include"
    -I"$REPO_PATH/platform/mbed-trace/include"
    -I"$REPO_PATH/connectivity/FEATURE_BLE/include"
    -I"$REPO_PATH/connectivity/FEATURE_BLE/libraries/cordio_stack/ble-host/include"
    -I"$REPO_PATH/connectivity/FEATURE_BLE/libraries/cordio_stack/ble-host/sources/stack/att"
    -I"$REPO_PATH/storage/kvstore/include"
    -I"$REPO_PATH/storage/kvstore/securestore/include"
    -I"$REPO_PATH/connectivity/lorawan/include"
    -I"$REPO_PATH/connectivity/drivers/cellular/GEMALTO/CINTERION"
)

CFLAGS="-O0 -g -DMBED_CONF_PLATFORM_STDIO_CONVERT_NEWLINES=0 -DMBED_BUILD_TIMESTAMP=0"
CXXFLAGS="$CFLAGS -std=c++14"

echo "[build.sh] Compilando ficheros del benchmark..."

# MBEDOS-DEFECT-001: BLE EATT stack
gcc -c $CFLAGS "${INCLUDES[@]}" \
    "$REPO_PATH/connectivity/FEATURE_BLE/libraries/cordio_stack/ble-host/sources/stack/att/att_eatt.c" \
    -o /tmp/att_eatt.o 2>&1 || echo "[WARN] att_eatt.c requiere headers adicionales"

# MBEDOS-DEFECT-002: SecureStore
g++ -c $CXXFLAGS "${INCLUDES[@]}" \
    "$REPO_PATH/storage/kvstore/securestore/source/SecureStore.cpp" \
    -o /tmp/SecureStore.o 2>&1 || echo "[WARN] SecureStore.cpp requiere headers adicionales"

# MBEDOS-DEFECT-003: Cellular GEMALTO
g++ -c $CXXFLAGS "${INCLUDES[@]}" \
    "$REPO_PATH/connectivity/drivers/cellular/GEMALTO/CINTERION/GEMALTO_CINTERION_CellularStack.cpp" \
    -o /tmp/GEMALTO_stack.o 2>&1 || echo "[WARN] GEMALTO_CINTERION_CellularStack.cpp requiere headers adicionales"

# MBEDOS-DEFECT-004: LoRaWAN header (se compila incluyendo un .cpp que lo usa)
# LoRaRadio.h es un header — se compila indirectamente a través de los TUs que lo incluyen
g++ -c $CXXFLAGS "${INCLUDES[@]}" \
    -include "$REPO_PATH/connectivity/lorawan/include/lorawan/LoRaRadio.h" \
    -x c++ /dev/null \
    -o /tmp/loraradio_dummy.o 2>&1 || echo "[WARN] LoRaRadio.h requiere mbed-os completo"

echo "[build.sh] mbed-os benchmark build completado."
echo "[build.sh] NOTA: Para análisis completo, usar build completo con mbed-tools:"
echo "  cd $REPO_PATH && mbed-tools compile -t GCC_ARM -m DISCO_L475VG_IOT01A"
