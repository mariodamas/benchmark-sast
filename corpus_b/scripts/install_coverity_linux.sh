#!/bin/bash
# corpus_b/scripts/install_coverity_linux.sh
# =============================================================================
# Prepara el entorno WSL2 para Coverity Linux cuando se disponga de licencia.
# Este script NO descarga Coverity (requiere cuenta Synopsys/Black Duck).
#
# Pasos manuales previos:
#   1. Descargar "Coverity Static Analysis" para Linux x64 desde:
#      https://community.synopsys.com/s/article/Coverity-Downloads
#      (requiere cuenta free tier o licencia comercial)
#   2. Colocar el instalador en /tmp/coverity_linux_installer.sh (o similar)
#   3. Ejecutar este script
#
# Uso:
#   bash corpus_b/scripts/install_coverity_linux.sh
#   bash corpus_b/scripts/install_coverity_linux.sh --installer /ruta/al/installer.sh
#   bash corpus_b/scripts/install_coverity_linux.sh --verify   # solo verificar instalación
#
# Variables de entorno:
#   COVERITY_HOME   — directorio de instalación (default: /opt/cov-analysis)
#   COVERITY_TOKEN  — token de autenticación para Synopsys (opcional)
# =============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
COVERITY_HOME="${COVERITY_HOME:-/opt/cov-analysis}"
INSTALLER_PATH="/tmp/coverity_linux_installer.sh"
MODE="install"

for arg in "$@"; do
    case "$arg" in
        --installer=*) INSTALLER_PATH="${arg#--installer=}" ;;
        --installer)   shift; INSTALLER_PATH="${1:-}" ;;
        --verify)      MODE="verify" ;;
        --help)
            echo "Uso: $0 [--installer /ruta] [--verify]"
            echo "  --installer PATH  Ruta al instalador de Coverity Linux (.sh)"
            echo "  --verify          Solo verificar instalación existente"
            exit 0
            ;;
    esac
done

echo ""
echo "================================================================"
echo "  Coverity Linux — Setup para benchmark corpus_b"
echo "================================================================"
echo ""

# ── Verificar instalación existente ──────────────────────────────────────────

verify_coverity() {
    local COV_BUILD="$COVERITY_HOME/bin/cov-build"
    local COV_ANALYZE="$COVERITY_HOME/bin/cov-analyze"
    local COV_ERRORS="$COVERITY_HOME/bin/cov-format-errors"

    if [[ ! -x "$COV_BUILD" ]]; then
        err "cov-build no encontrado en $COVERITY_HOME/bin/"
        return 1
    fi
    if [[ ! -x "$COV_ANALYZE" ]]; then
        err "cov-analyze no encontrado"
        return 1
    fi
    if [[ ! -x "$COV_ERRORS" ]]; then
        err "cov-format-errors no encontrado"
        return 1
    fi

    local VERSION
    VERSION=$("$COV_BUILD" --version 2>&1 | head -1 || echo "desconocida")
    ok "Coverity instalado en $COVERITY_HOME"
    ok "Versión: $VERSION"

    # Verificar licencia
    info "Verificando licencia..."
    if "$COV_BUILD" --dir /tmp/cov_test_dir --test-build bash -c "echo test" &>/dev/null; then
        ok "Licencia válida (cov-build funcional)"
        rm -rf /tmp/cov_test_dir
    else
        warn "cov-build falló — puede ser problema de licencia"
        warn "Verificar: $COVERITY_HOME/bin/cov-configure --list-compilers"
    fi

    return 0
}

if [[ "$MODE" == "verify" ]]; then
    verify_coverity
    exit $?
fi

# ── Modo instalación ──────────────────────────────────────────────────────────

# Si ya está instalado, solo verificar
if [[ -x "$COVERITY_HOME/bin/cov-build" ]]; then
    info "Coverity ya instalado en $COVERITY_HOME"
    verify_coverity
    echo ""
    info "Para actualizar la configuración del benchmark, continúa más abajo."
else
    # Verificar que el instalador existe
    if [[ ! -f "$INSTALLER_PATH" ]]; then
        warn "Instalador no encontrado: $INSTALLER_PATH"
        echo ""
        echo "Para instalar Coverity:"
        echo ""
        echo "  1. Crear cuenta gratuita en Synopsys Black Duck Developer Hub:"
        echo "     https://community.synopsys.com/"
        echo ""
        echo "  2. Descargar Coverity Static Analysis (Linux x64):"
        echo "     Buscar 'Coverity Static Analysis Downloads' en el portal"
        echo "     Seleccionar versión >= 2023.x"
        echo ""
        echo "  3. Transferir el instalador a WSL2:"
        echo "     cp /mnt/c/Users/mario/Downloads/cov-analysis-linux64-*.sh $INSTALLER_PATH"
        echo ""
        echo "  4. Ejecutar este script:"
        echo "     bash corpus_b/scripts/install_coverity_linux.sh --installer $INSTALLER_PATH"
        echo ""
        echo "Alternativa: Coverity en Windows + integración vía scripts"
        echo "  Ver: corpus_b/results/PENDIENTE_COVERITY.md"
        exit 0
    fi

    # Instalar
    info "Instalando Coverity desde $INSTALLER_PATH..."
    info "Destino: $COVERITY_HOME"
    mkdir -p "$COVERITY_HOME"

    chmod +x "$INSTALLER_PATH"
    sudo "$INSTALLER_PATH" -- \
        --installation.dir="$COVERITY_HOME" \
        --mode=silent

    if verify_coverity; then
        ok "Coverity instalado correctamente"
    else
        err "Instalación fallida. Ver log del instalador."
        exit 1
    fi
fi

echo ""

# ── Configurar Coverity para compiladores del benchmark ──────────────────────
echo "--- Configuración de compiladores ---"

COV_CONFIGURE="$COVERITY_HOME/bin/cov-configure"

# GCC (proyectos embedded: NuttX, Contiki-NG, epk2extract)
if command -v gcc &>/dev/null; then
    info "Configurando gcc..."
    "$COV_CONFIGURE" --gcc
    ok "gcc configurado"
fi

# GCC ARM (mbed-os cross-compilation)
if command -v arm-none-eabi-gcc &>/dev/null; then
    info "Configurando arm-none-eabi-gcc..."
    "$COV_CONFIGURE" --template --compiler arm-none-eabi-gcc --comptype gcc
    ok "arm-none-eabi-gcc configurado"
else
    warn "arm-none-eabi-gcc no encontrado — mbed-os puede necesitar cross-compiler"
    warn "  sudo apt install gcc-arm-none-eabi"
fi

# CMake + make (raylib)
if command -v cmake &>/dev/null; then
    ok "cmake disponible (raylib OK)"
fi

echo ""

# ── Actualizar .env.benchmark ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_ROOT="${BENCHMARK_ROOT:-$(realpath "$SCRIPT_DIR/../..")}"
ENV_FILE="$BENCHMARK_ROOT/.env.benchmark"

echo "--- Actualizar .env.benchmark ---"

if [[ -f "$ENV_FILE" ]]; then
    # Actualizar o añadir COVERITY_HOME
    if grep -q "^COVERITY_HOME=" "$ENV_FILE"; then
        sed -i "s|^COVERITY_HOME=.*|COVERITY_HOME=$COVERITY_HOME|" "$ENV_FILE"
        ok "COVERITY_HOME actualizado en .env.benchmark"
    elif grep -q "^# COVERITY_HOME=" "$ENV_FILE"; then
        sed -i "s|^# COVERITY_HOME=.*|COVERITY_HOME=$COVERITY_HOME|" "$ENV_FILE"
        ok "COVERITY_HOME descomentado en .env.benchmark"
    else
        echo "COVERITY_HOME=$COVERITY_HOME" >> "$ENV_FILE"
        ok "COVERITY_HOME añadido a .env.benchmark"
    fi
else
    warn ".env.benchmark no encontrado en $BENCHMARK_ROOT"
    warn "Crear manualmente y añadir: COVERITY_HOME=$COVERITY_HOME"
fi

echo ""

# ── Instrucciones para activar Fase C ────────────────────────────────────────
echo "================================================================"
echo "  Coverity listo para corpus_b"
echo "================================================================"
echo ""
echo "Para ejecutar el benchmark completo (CodeQL + Coverity):"
echo ""
echo "  cd $BENCHMARK_ROOT"
echo "  python corpus_b/runner/parallel_runner.py"
echo ""
echo "Para ejecutar solo Fase C (Coverity, si Fases A y B ya completadas):"
echo ""
echo "  python corpus_b/runner/parallel_runner.py --phase C"
echo "  # o equivalentemente:"
echo "  python corpus_b/runner/parallel_runner.py --only-coverity"
echo ""
echo "Ver estado en tiempo real:"
echo ""
echo "  bash corpus_b/scripts/monitor.sh"
echo ""

# Actualizar PENDIENTE_COVERITY.md
PENDIENTE="$BENCHMARK_ROOT/corpus_b/results/PENDIENTE_COVERITY.md"
if [[ -f "$PENDIENTE" ]]; then
    FECHA=$(date '+%Y-%m-%d')
    # Añadir registro al final del fichero
    echo "" >> "$PENDIENTE"
    echo "## Actualización $FECHA" >> "$PENDIENTE"
    echo "" >> "$PENDIENTE"
    echo "- Coverity instalado en: $COVERITY_HOME" >> "$PENDIENTE"
    echo "- Script ejecutado por: $(whoami)@$(hostname)" >> "$PENDIENTE"
    ok "Registro añadido a PENDIENTE_COVERITY.md"
fi
