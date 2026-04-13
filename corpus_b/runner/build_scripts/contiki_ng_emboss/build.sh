#!/bin/bash
# =============================================================================
# build.sh — contiki-ng/contiki-ng
# Compatible con:
#   codeql database create --command="bash ./build.sh" ...
#   cov-build --dir cov_dir bash ./build.sh
#
# Dependencias:
#   apt-get install -y gcc make python3 python3-pip
#   pip3 install pyserial
#
# Target: native (simulación software en host, no requiere hardware embebido)
#   Compila los ejemplos hello-world y rpl-udp con TARGET=native,
#   incluyendo los módulos de red IPv6, BLE, y routing que contienen
#   los defectos del benchmark.
#
# Variables de entorno requeridas:
#   REPO_PATH — ruta absoluta al repositorio clonado de contiki-ng
#
# Ficheros clave compilados (contienen los defectos del benchmark):
#   os/net/app-layer/coap/coap-uip.c   (CONTIKI-DEFECT-001)
#   os/net/app-layer/snmp/snmp.c       (CONTIKI-DEFECT-002)
#   os/net/mac/ble/ble-l2cap.c         (CONTIKI-DEFECT-003, 004, 005)
# =============================================================================

set -euo pipefail

: "${REPO_PATH:?ERROR: REPO_PATH no definido. Exporta la ruta al repo de contiki-ng.}"

cd "$REPO_PATH"

echo "[build.sh] Contiki-NG native build — $(pwd)"
echo "[build.sh] Commit: $(git rev-parse HEAD)"

# Build 1: hello-world con todos los módulos de red relevantes
# Incluye coap-uip.c, snmp.c, rpl-*.c, esmrf.c
make -C examples/hello-world \
    TARGET=native \
    MODULES="os/net/ipv6 os/net/routing os/net/mac os/net/app-layer/coap os/net/app-layer/snmp" \
    CFLAGS="-O0 -g" \
    -j"$(nproc)" \
    2>&1 || true   # 'true' porque algunos módulos pueden no compilar en native

# Build 2: ejemplo rpl-udp para incluir el módulo RPL completo
make -C examples/rpl-udp \
    TARGET=native \
    CFLAGS="-O0 -g" \
    -j"$(nproc)" \
    2>&1 || true

# Build 3: compilar explícitamente el módulo BLE L2CAP
# (no se incluye automáticamente en TARGET=native)
# Forzar compilación directa para que CodeQL capture las TUs de BLE
gcc -c -O0 -g \
    -I"$REPO_PATH" \
    -I"$REPO_PATH/os" \
    -I"$REPO_PATH/os/lib" \
    -I"$REPO_PATH/arch/cpu/native" \
    -DCONTIKI_TARGET_NATIVE=1 \
    -DBUILD_WITH_SHELL=1 \
    "$REPO_PATH/os/net/mac/ble/ble-l2cap.c" \
    -o /tmp/ble_l2cap_build.o \
    2>&1 || echo "[build.sh] WARN: ble-l2cap.c requiere dependencias adicionales — revisar includes"

echo "[build.sh] Contiki-NG native build completado."
