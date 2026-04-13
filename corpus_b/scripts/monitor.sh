#!/bin/bash
# corpus_b/scripts/monitor.sh
# =============================================================================
# Monitorización en tiempo real del benchmark corpus_b.
# Muestra progreso de builds, análisis CodeQL y Coverity.
#
# Uso:
#   bash corpus_b/scripts/monitor.sh
#   bash corpus_b/scripts/monitor.sh --once    # imprimir estado y salir
#   bash corpus_b/scripts/monitor.sh --log     # también seguir el log activo
#
# Variables de entorno:
#   RESULTS_BASE  — directorio de resultados (default: /tmp/benchmark_results)
#   REPOS_BASE    — directorio de repos (default: /tmp/repos_b)
#   REFRESH_SECS  — intervalo de refresco en modo watch (default: 15)
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
RESULTS_BASE="${RESULTS_BASE:-/tmp/benchmark_results}"
REPOS_BASE="${REPOS_BASE:-/tmp/repos_b}"
REFRESH_SECS="${REFRESH_SECS:-15}"
MODE="watch"  # watch | once | log

# Parsear args
for arg in "$@"; do
    case "$arg" in
        --once) MODE="once" ;;
        --log)  MODE="log" ;;
        --help) echo "Uso: $0 [--once|--log]"; exit 0 ;;
    esac
done

# ── Proyectos y sus instancias esperadas ──────────────────────────────────────
declare -A PROJECT_IDS=(
    ["apache_nuttx"]="NUTTX-DEFECT-001 NUTTX-DEFECT-002 NUTTX-DEFECT-003 NUTTX-DEFECT-004 NUTTX-DEFECT-005"
    ["contiki_ng"]="CONTIKI-DEFECT-001 CONTIKI-DEFECT-002 CONTIKI-DEFECT-003 CONTIKI-DEFECT-004"
    ["raylib"]="RAYLIB-DEFECT-001 RAYLIB-DEFECT-002 RAYLIB-DEFECT-003 RAYLIB-DEFECT-004 RAYLIB-DEFECT-005"
    ["mbed_os"]="MBEDOS-DEFECT-001 MBEDOS-DEFECT-002 MBEDOS-DEFECT-003 MBEDOS-DEFECT-004"
    ["epk2extract"]="EPK2-DEFECT-001 EPK2-DEFECT-002 EPK2-DEFECT-003 EPK2-DEFECT-004"
)

# ── Colores ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Funciones de estado ───────────────────────────────────────────────────────

count_files() {
    local PATTERN="$1"
    find "$RESULTS_BASE" -path "$PATTERN" 2>/dev/null | wc -l
}

check_db() {
    local PROJECT="$1" ID="$2" VERSION="$3"
    local DB_PATH="$RESULTS_BASE/codeql/$PROJECT/$ID/$VERSION/db"
    [[ -d "$DB_PATH" ]] && echo "ok" || echo "--"
}

check_sarif() {
    local PROJECT="$1" ID="$2" VERSION="$3"
    local SARIF="$RESULTS_BASE/codeql/$PROJECT/$ID/${VERSION}.sarif"
    if [[ -f "$SARIF" ]]; then
        local ALERTS
        ALERTS=$(python3 -c "
import json, sys
try:
    d = json.load(open('$SARIF'))
    n = sum(len(r.get('results',[])) for r in d.get('runs',[]))
    print(n)
except: print('?')
" 2>/dev/null)
        echo "$ALERTS"
    else
        echo "--"
    fi
}

check_cov_json() {
    local PROJECT="$1" ID="$2" VERSION="$3"
    local JSON="$RESULTS_BASE/coverity/$PROJECT/$ID/${VERSION}.json"
    [[ -f "$JSON" ]] && echo "ok" || echo "--"
}

check_invalid_build() {
    local PROJECT="$1" ID="$2" VERSION="$3"
    local LOG="$RESULTS_BASE/logs/build_${ID}_${VERSION}.log"
    if [[ -f "$LOG" ]] && grep -q "INVALID_BUILD\|ausente en src.zip" "$LOG" 2>/dev/null; then
        echo "INVALID"
    else
        echo ""
    fi
}

# ── Renderizar tabla de estado ────────────────────────────────────────────────

print_status() {
    local TIMESTAMP
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

    clear
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Benchmark SAST corpus_b — Monitor  ($TIMESTAMP)${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}  RESULTS_BASE: $RESULTS_BASE${NC}"
    echo ""

    # Cabecera tabla
    printf "  %-25s %-5s %-5s %-8s %-8s %-8s %-8s\n" \
        "INSTANCIA" "DB_V" "DB_S" "SARIF_V" "SARIF_S" "COV_V" "COV_S"
    echo "  ─────────────────────────────────────────────────────────────────────"

    local TOTAL=0 DB_DONE=0 SARIF_DONE=0 COV_DONE=0 INVALID=0

    for PROJECT in apache_nuttx contiki_ng raylib mbed_os epk2extract; do
        local IDS="${PROJECT_IDS[$PROJECT]:-}"
        if [[ -z "$IDS" ]]; then continue; fi

        echo -e "  ${CYAN}[$PROJECT]${NC}"

        for ID in $IDS; do
            TOTAL=$((TOTAL + 1))

            DB_V=$(check_db "$PROJECT" "$ID" "V")
            DB_S=$(check_db "$PROJECT" "$ID" "S")
            SARIF_V=$(check_sarif "$PROJECT" "$ID" "V")
            SARIF_S=$(check_sarif "$PROJECT" "$ID" "S")
            COV_V=$(check_cov_json "$PROJECT" "$ID" "V")
            COV_S=$(check_cov_json "$PROJECT" "$ID" "S")
            INV_V=$(check_invalid_build "$PROJECT" "$ID" "V")
            INV_S=$(check_invalid_build "$PROJECT" "$ID" "S")

            # Contar completados
            [[ "$DB_V" == "ok" && "$DB_S" == "ok" ]] && DB_DONE=$((DB_DONE + 1))
            [[ "$SARIF_V" != "--" && "$SARIF_S" != "--" ]] && SARIF_DONE=$((SARIF_DONE + 1))
            [[ "$COV_V" == "ok" && "$COV_S" == "ok" ]] && COV_DONE=$((COV_DONE + 1))
            [[ -n "$INV_V" || -n "$INV_S" ]] && INVALID=$((INVALID + 1))

            # Color por estado
            DB_V_C="${DB_V}"; [[ "$DB_V" == "ok" ]] && DB_V_C="${GREEN}ok${NC}"   || DB_V_C="${RED}--${NC}"
            DB_S_C="${DB_S}"; [[ "$DB_S" == "ok" ]] && DB_S_C="${GREEN}ok${NC}"   || DB_S_C="${RED}--${NC}"

            color_sarif() {
                local VAL="$1"
                if [[ "$VAL" == "--" ]]; then echo "${RED}--${NC}"; return; fi
                if [[ "$VAL" == "0" ]]; then echo "${YELLOW}0${NC}"; return; fi
                echo "${GREEN}${VAL}${NC}"
            }
            SARIF_V_C=$(color_sarif "$SARIF_V")
            SARIF_S_C=$(color_sarif "$SARIF_S")

            COV_V_C="${COV_V}"; [[ "$COV_V" == "ok" ]] && COV_V_C="${GREEN}ok${NC}" || COV_V_C="--"
            COV_S_C="${COV_S}"; [[ "$COV_S" == "ok" ]] && COV_S_C="${GREEN}ok${NC}" || COV_S_C="--"

            SUFFIX=""
            [[ -n "$INV_V" || -n "$INV_S" ]] && SUFFIX=" ${YELLOW}[INVALID_BUILD]${NC}"

            printf "  %-25s " "$ID"
            echo -ne "${DB_V_C}     ${DB_S_C}     ${SARIF_V_C}       ${SARIF_S_C}       ${COV_V_C}     ${COV_S_C}${SUFFIX}\n"
        done
        echo ""
    done

    # Resumen
    echo "  ─────────────────────────────────────────────────────────────────────"
    echo -e "  ${BOLD}RESUMEN${NC}"
    echo -e "  Total instancias  : $TOTAL"
    echo -e "  DBs completadas   : ${GREEN}$DB_DONE${NC}/$TOTAL (Fase A)"
    echo -e "  SARIFs generados  : ${GREEN}$SARIF_DONE${NC}/$TOTAL (Fase B)"
    echo -e "  Coverity JSONs    : ${GREEN}$COV_DONE${NC}/$TOTAL (Fase C)"
    [[ $INVALID -gt 0 ]] && echo -e "  Invalid builds    : ${YELLOW}$INVALID${NC} (revisar build scripts)"
    echo ""

    # Proceso activo
    local RUNNER_PID
    RUNNER_PID=$(pgrep -f "parallel_runner.py" 2>/dev/null | head -1 || true)
    if [[ -n "$RUNNER_PID" ]]; then
        echo -e "  ${GREEN}Runner activo: PID $RUNNER_PID${NC}"
        echo -e "  CPU: $(ps -p "$RUNNER_PID" -o %cpu= 2>/dev/null | tr -d ' ')%   MEM: $(ps -p "$RUNNER_PID" -o %mem= 2>/dev/null | tr -d ' ')%"
    else
        echo -e "  ${YELLOW}Runner: no activo${NC}"
    fi

    # Log más reciente
    local LATEST_LOG
    LATEST_LOG=$(find "$RESULTS_BASE/logs" -name "benchmark_*.log" 2>/dev/null \
        | sort -t_ -k2 -r | head -1 || true)
    if [[ -n "$LATEST_LOG" ]]; then
        echo ""
        echo -e "  ${CYAN}Log activo: $LATEST_LOG${NC}"
        echo "  Últimas 5 líneas:"
        tail -5 "$LATEST_LOG" 2>/dev/null | sed 's/^/    /'
    fi

    echo ""
    echo -e "  Refrescando cada ${REFRESH_SECS}s. Ctrl+C para salir."
    echo -e "  Para ver log completo: tail -f $LATEST_LOG"
}

# ── Modo log ──────────────────────────────────────────────────────────────────

follow_log() {
    local LATEST_LOG
    LATEST_LOG=$(find "$RESULTS_BASE/logs" -name "benchmark_*.log" 2>/dev/null \
        | sort -t_ -k2 -r | head -1 || true)
    if [[ -z "$LATEST_LOG" ]]; then
        echo "No hay logs en $RESULTS_BASE/logs/ — esperar a que arranque el runner"
        sleep 5
        follow_log
        return
    fi
    echo "Siguiendo: $LATEST_LOG"
    echo "─────────────────────────────────────"
    tail -f "$LATEST_LOG"
}

# ── Main ──────────────────────────────────────────────────────────────────────

if [[ ! -d "$RESULTS_BASE" ]]; then
    echo "RESULTS_BASE no existe todavía: $RESULTS_BASE"
    echo "Esperando a que arranque el runner..."
    sleep 5
fi

case "$MODE" in
    once)
        print_status
        ;;
    log)
        follow_log
        ;;
    watch)
        while true; do
            print_status
            sleep "$REFRESH_SECS"
        done
        ;;
esac
