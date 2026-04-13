#!/bin/bash
# corpus_b/scripts/setup_wsl2.sh
# =============================================================================
# Configura el entorno WSL2 para ejecutar el benchmark corpus_b.
# Cubre las Tareas 1-5: verificar entorno, instalar CodeQL, clonar repos,
# validar dependencias de build.
#
# Uso (desde WSL2, cualquier directorio):
#   bash /mnt/c/Users/mario/Desktop/INFORMATICA/4\ Curso/TFG/sast-benchmark/corpus_b/scripts/setup_wsl2.sh
#
# O con BENCHMARK_ROOT ya exportado:
#   bash "$BENCHMARK_ROOT/corpus_b/scripts/setup_wsl2.sh"
#
# Variables de entorno respetadas (precedencia sobre defaults):
#   BENCHMARK_ROOT  — raíz del repo en WSL2 (auto-detectada si no está definida)
#   CODEQL_BINARY   — ruta al binario codeql (default: /usr/local/bin/codeql)
#   REPOS_BASE      — directorio de repos clonados (default: /tmp/repos_b)
#   CODEQL_VERSION  — versión a instalar si no está presente (default: 2.20.4)
# =============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }

# ── Auto-detectar BENCHMARK_ROOT ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_ROOT="${BENCHMARK_ROOT:-$(realpath "$SCRIPT_DIR/../..")}"
ENV_FILE="$BENCHMARK_ROOT/.env.benchmark"

info "BENCHMARK_ROOT = $BENCHMARK_ROOT"

# Cargar .env.benchmark si existe
if [[ -f "$ENV_FILE" ]]; then
    info "Cargando configuración desde $ENV_FILE"
    # shellcheck disable=SC1090
    set -o allexport
    source "$ENV_FILE"
    set +o allexport
fi

CODEQL_BINARY="${CODEQL_BINARY:-/usr/local/bin/codeql}"
REPOS_BASE="${REPOS_BASE:-/tmp/repos_b}"
CODEQL_VERSION="${CODEQL_VERSION:-2.20.4}"

echo ""
echo "============================================================"
echo "  Benchmark SAST — Setup WSL2 (corpus_b / EMBOSS)"
echo "============================================================"
echo ""

# ── TAREA 1: Verificar entorno WSL2 ──────────────────────────────────────────
echo "--- TAREA 1: Verificar entorno ---"

# Sistema operativo
OS_INFO=$(uname -a)
info "Sistema: $OS_INFO"

if ! grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    warn "No parece estar en WSL2. El benchmark está diseñado para WSL2."
    warn "Continúa solo si sabes lo que haces."
fi

# Python 3.10+
if ! command -v python3 &>/dev/null; then
    err "Python3 no encontrado. Instalar: sudo apt install python3"
    exit 1
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Python: $PY_VER"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    ok "Python >= 3.10"
else
    err "Python 3.10+ requerido (actual: $PY_VER)"
    exit 1
fi

# Dependencias Python
for pkg in yaml; do
    if python3 -c "import $pkg" 2>/dev/null; then
        ok "python3-$pkg disponible"
    else
        warn "python3-$pkg no encontrado. Instalando..."
        pip3 install "pyyaml" 2>/dev/null || sudo apt install -y python3-yaml
    fi
done

# Git
if ! command -v git &>/dev/null; then
    err "git no encontrado. Instalar: sudo apt install git"
    exit 1
fi
ok "git $(git --version | awk '{print $3}')"

# Make, CMake, gcc
for tool in make cmake gcc g++; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool: $($tool --version 2>&1 | head -1)"
    else
        warn "$tool no encontrado — puede ser necesario para algunos proyectos"
    fi
done

echo ""

# ── TAREA 2: Instalar CodeQL ──────────────────────────────────────────────────
echo "--- TAREA 2: CodeQL ---"

if [[ -x "$CODEQL_BINARY" ]]; then
    CQL_VER=$("$CODEQL_BINARY" --version 2>&1 | head -1)
    ok "CodeQL ya instalado: $CQL_VER"
    ok "Binario: $CODEQL_BINARY"
else
    warn "CodeQL no encontrado en $CODEQL_BINARY"
    info "Instalando CodeQL $CODEQL_VERSION..."

    CODEQL_INSTALL_DIR="$(dirname "$CODEQL_BINARY")"
    CODEQL_ZIP="/tmp/codeql-linux64.zip"
    CODEQL_URL="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz"

    # Descargar
    info "Descargando CodeQL bundle $CODEQL_VERSION (~1.5GB)..."
    if command -v curl &>/dev/null; then
        curl -L "$CODEQL_URL" -o "/tmp/codeql-bundle.tar.gz" --progress-bar
    elif command -v wget &>/dev/null; then
        wget -q --show-progress "$CODEQL_URL" -O "/tmp/codeql-bundle.tar.gz"
    else
        err "curl o wget requerido para descargar CodeQL"
        exit 1
    fi

    # Extraer
    info "Extrayendo en /tmp/codeql-bundle/..."
    mkdir -p /tmp/codeql-bundle
    tar -xzf /tmp/codeql-bundle.tar.gz -C /tmp/codeql-bundle
    rm -f /tmp/codeql-bundle.tar.gz

    # Instalar
    EXTRACTED_DIR=/tmp/codeql-bundle/codeql
    if [[ ! -d "$EXTRACTED_DIR" ]]; then
        err "Extracción fallida: no se encontró $EXTRACTED_DIR"
        exit 1
    fi

    INSTALL_PARENT=$(dirname "$CODEQL_INSTALL_DIR")
    if [[ "$INSTALL_PARENT" == "/usr/local" ]]; then
        sudo mv "$EXTRACTED_DIR" "/usr/local/codeql"
        sudo ln -sf "/usr/local/codeql/codeql" "$CODEQL_BINARY"
    else
        mkdir -p "$CODEQL_INSTALL_DIR"
        mv "$EXTRACTED_DIR" "$CODEQL_INSTALL_DIR/codeql-dist"
        ln -sf "$CODEQL_INSTALL_DIR/codeql-dist/codeql" "$CODEQL_BINARY"
    fi

    if "$CODEQL_BINARY" --version &>/dev/null; then
        ok "CodeQL instalado correctamente: $("$CODEQL_BINARY" --version | head -1)"
    else
        err "Instalación de CodeQL fallida"
        exit 1
    fi
fi

# Verificar paquete de queries C++
info "Verificando paquete cpp-queries..."
if "$CODEQL_BINARY" resolve queries codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \
    &>/dev/null; then
    ok "cpp-security-extended.qls disponible"
else
    warn "Paquete cpp-queries no disponible. Descargando..."
    "$CODEQL_BINARY" pack download codeql/cpp-queries
    ok "cpp-queries descargado"
fi

echo ""

# ── TAREA 3: Crear directorio de repos ───────────────────────────────────────
echo "--- TAREA 3: Directorios ---"

mkdir -p "$REPOS_BASE"
ok "REPOS_BASE = $REPOS_BASE"

RESULTS_BASE="${RESULTS_BASE:-/tmp/benchmark_results}"
mkdir -p "$RESULTS_BASE/logs"
ok "RESULTS_BASE = $RESULTS_BASE"

echo ""

# ── TAREA 4: Clonar repositorios ─────────────────────────────────────────────
echo "--- TAREA 4: Clonar repositorios corpus_b ---"

declare -A REPOS=(
    ["apache_nuttx"]="https://github.com/apache/nuttx"
    ["contiki_ng"]="https://github.com/contiki-ng/contiki-ng"
    ["raylib"]="https://github.com/raysan5/raylib"
    ["mbed_os"]="https://github.com/ARMmbed/mbed-os"
    ["epk2extract"]="https://github.com/openlgtv/epk2extract"
)

for PROJECT in "${!REPOS[@]}"; do
    REPO_URL="${REPOS[$PROJECT]}"
    REPO_PATH="$REPOS_BASE/$PROJECT"

    if [[ -d "$REPO_PATH/.git" ]]; then
        ok "$PROJECT: ya clonado en $REPO_PATH"
        # Fetch silencioso para tener todos los commits necesarios
        git -C "$REPO_PATH" fetch --quiet origin 2>/dev/null || warn "$PROJECT: fetch falló (sin conexión?)"
    else
        info "Clonando $PROJECT (~puede tardar varios minutos)..."
        git clone --quiet "$REPO_URL" "$REPO_PATH" 2>&1 | tail -3
        if [[ -d "$REPO_PATH/.git" ]]; then
            ok "$PROJECT: clonado en $REPO_PATH"
        else
            err "$PROJECT: clone fallido"
        fi
    fi
done

echo ""

# ── TAREA 5: Dependencias de build por proyecto ───────────────────────────────
echo "--- TAREA 5: Dependencias de build ---"

BUILD_SCRIPTS_DIR="$BENCHMARK_ROOT/corpus_b/runner/build_scripts"

check_build_deps() {
    local PROJECT="$1"
    local SCRIPT="$BUILD_SCRIPTS_DIR/$PROJECT/build.sh"

    if [[ ! -f "$SCRIPT" ]]; then
        warn "$PROJECT: build script no encontrado ($SCRIPT)"
        return 1
    fi
    chmod +x "$SCRIPT"
    ok "$PROJECT: build.sh ejecutable"
}

# apache_nuttx — necesita kconfig-frontends
check_build_deps "apache_nuttx"
if ! command -v kconfig-mconf &>/dev/null; then
    warn "apache_nuttx: kconfig-frontends no instalado"
    warn "  Instalar: sudo apt install kconfig-frontends"
else
    ok "apache_nuttx: kconfig-frontends disponible"
fi

# contiki-ng — necesita gcc + make (ya verificados)
check_build_deps "contiki_ng"

# raylib — necesita libGL + libXi + libXcursor
check_build_deps "raylib"
RAYLIB_DEPS=("libgl1-mesa-dev" "libxi-dev" "libxcursor-dev" "libx11-dev")
for DEP in "${RAYLIB_DEPS[@]}"; do
    if dpkg -l "$DEP" &>/dev/null 2>&1; then
        ok "raylib: $DEP instalado"
    else
        warn "raylib: $DEP no instalado — instalar con: sudo apt install $DEP"
    fi
done

# mbed_os — necesita Python 3 + mbed-tools o cmake
check_build_deps "mbed_os"
if command -v mbed-tools &>/dev/null; then
    ok "mbed_os: mbed-tools disponible"
else
    warn "mbed_os: mbed-tools no instalado (opcional)"
    warn "  pip3 install mbed-tools"
fi

# epk2extract — necesita cmake + openssl-dev
check_build_deps "epk2extract"
if dpkg -l libssl-dev &>/dev/null 2>&1; then
    ok "epk2extract: libssl-dev instalado"
else
    warn "epk2extract: libssl-dev no instalado"
    warn "  sudo apt install libssl-dev"
fi

echo ""

# ── Resumen ───────────────────────────────────────────────────────────────────
echo "============================================================"
echo "  Resumen del setup"
echo "============================================================"
echo ""
info "BENCHMARK_ROOT : $BENCHMARK_ROOT"
info "CODEQL_BINARY  : $CODEQL_BINARY"
info "REPOS_BASE     : $REPOS_BASE"
info "RESULTS_BASE   : $RESULTS_BASE"
echo ""
echo "Repos clonados:"
for PROJECT in apache_nuttx contiki_ng raylib mbed_os epk2extract; do
    REPO_PATH="$REPOS_BASE/$PROJECT"
    if [[ -d "$REPO_PATH/.git" ]]; then
        COMMITS=$(git -C "$REPO_PATH" rev-list --count HEAD 2>/dev/null || echo "?")
        echo "  $PROJECT: $REPO_PATH ($COMMITS commits)"
    else
        echo "  $PROJECT: NO CLONADO"
    fi
done

echo ""
ok "Setup completado."
echo ""
echo "Siguiente paso — ejecutar el benchmark:"
echo "  cd $BENCHMARK_ROOT"
echo "  python corpus_b/runner/parallel_runner.py --skip-coverity"
echo ""
echo "Para monitorizar el progreso en otra terminal:"
echo "  bash corpus_b/scripts/monitor.sh"
echo ""
