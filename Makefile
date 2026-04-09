# =============================================================================
# Makefile — Benchmark SAST: CodeQL vs Coverity vs Unión
# TFG Mario Damas Sánchez — UCLM 2026
#
# VARIABLES DE ENTORNO REQUERIDAS:
#   CODEQL_HOME    — directorio de la instalación de CodeQL  (default: /opt/codeql)
#   COVERITY_HOME  — directorio de la instalación de Coverity (default: /opt/cov-analysis)
#
# USO:
#   make help                 → muestra este mensaje
#   make validate             → valida los ground truth YAML
#   make run-codeql-mbedtls   → ejecuta CodeQL sobre mbedTLS
#   make run-coverity-mbedtls → ejecuta Coverity sobre mbedTLS
#   make dedup-mbedtls        → deduplicación mbedTLS
#   make metrics-mbedtls      → métricas mbedTLS
#   make run-wolfssl          → pipeline completo sobre wolfSSL (validación)
#   make all                  → pipeline completo mbedTLS + wolfSSL + cross
#   make report               → genera informe final en Markdown
#   make clean-results        → elimina resultados generados (NO el ground truth)
# =============================================================================

PYTHON        := python3
CODEQL_HOME   ?= /opt/codeql
COVERITY_HOME ?= /opt/cov-analysis
THREADS       ?= 4
LINE_WINDOW   ?= 10
MBED_KLOC     := 60
WOLFSSL_KLOC  := 45

REPO_ROOT     := $(shell pwd)
REPOS_DIR     := /tmp/sast-benchmark-repos

# ---------------------------------------------------------------------------
.DEFAULT_GOAL := help

.PHONY: help validate \
        clone-mbedtls run-codeql-mbedtls run-coverity-mbedtls \
        dedup-mbedtls eval-mbedtls metrics-mbedtls \
        clone-wolfssl run-codeql-wolfssl run-coverity-wolfssl \
        dedup-wolfssl eval-wolfssl metrics-wolfssl \
        cross-project report all clean-results check-env

help:
	@echo ""
	@echo "  Benchmark SAST — CodeQL vs Coverity vs Unión"
	@echo "  ─────────────────────────────────────────────"
	@echo "  Targets disponibles:"
	@echo ""
	@echo "    validate               Valida los ground truth YAML"
	@echo "    run-codeql-mbedtls     CodeQL sobre mbedTLS (V + S por CVE)"
	@echo "    run-coverity-mbedtls   Coverity sobre mbedTLS (V + S por CVE)"
	@echo "    dedup-mbedtls          Deduplicación de findings mbedTLS"
	@echo "    eval-mbedtls           Evaluación de instancias mbedTLS"
	@echo "    metrics-mbedtls        Cálculo de métricas mbedTLS"
	@echo "    run-wolfssl            Pipeline completo wolfSSL (validación)"
	@echo "    cross-project          Análisis de consistencia cross-project"
	@echo "    report                 Informe final en Markdown"
	@echo "    all                    Pipeline completo (mbedTLS + wolfSSL + cross)"
	@echo "    clean-results          Limpia results/ (NO toca corpus/ ni scripts/)"
	@echo ""
	@echo "  Variables:"
	@echo "    CODEQL_HOME=$(CODEQL_HOME)"
	@echo "    COVERITY_HOME=$(COVERITY_HOME)"
	@echo "    THREADS=$(THREADS)"
	@echo "    LINE_WINDOW=$(LINE_WINDOW)"
	@echo ""

# ---------------------------------------------------------------------------
# Comprobación de entorno
# ---------------------------------------------------------------------------
check-env:
	@echo "Comprobando entorno..."
	@$(PYTHON) --version
	@$(PYTHON) -c "import yaml" 2>/dev/null || (echo "ERROR: pyyaml no instalado. Ejecuta: pip install pyyaml" && exit 1)
	@test -f "$(CODEQL_HOME)/codeql" || (echo "AVISO: CodeQL no encontrado en $(CODEQL_HOME)/codeql" && echo "       Exporta CODEQL_HOME=/ruta/a/codeql")
	@test -f "$(COVERITY_HOME)/bin/cov-build" || (echo "AVISO: Coverity no encontrado en $(COVERITY_HOME)/bin/cov-build" && echo "       Exporta COVERITY_HOME=/ruta/a/cov-analysis")
	@echo "OK"

# ---------------------------------------------------------------------------
# Validación
# ---------------------------------------------------------------------------
validate: check-env
	$(PYTHON) scripts/validate_ground_truth.py \
		--gt corpus/mbedtls/ground_truth.yaml \
		--gt corpus/wolfssl/ground_truth.yaml

# ---------------------------------------------------------------------------
# mbedTLS — Fase Principal
# ---------------------------------------------------------------------------
clone-mbedtls:
	@if [ ! -d "$(REPOS_DIR)/mbedtls" ]; then \
		git clone --quiet https://github.com/Mbed-TLS/mbedtls.git $(REPOS_DIR)/mbedtls; \
		echo "Clonado mbedTLS en $(REPOS_DIR)/mbedtls"; \
	else \
		echo "mbedTLS ya clonado."; \
	fi

run-codeql-mbedtls: validate clone-mbedtls
	$(PYTHON) runner/codeql/run_codeql.py \
		--ground-truth corpus/mbedtls/ground_truth.yaml \
		--repo-path $(REPOS_DIR)/mbedtls \
		--output-dir results/raw/codeql/mbedtls \
		--codeql-binary $(CODEQL_HOME)/codeql \
		--threads $(THREADS) \
		--skip-existing

run-coverity-mbedtls: validate clone-mbedtls
	$(PYTHON) runner/coverity/run_coverity.py \
		--ground-truth corpus/mbedtls/ground_truth.yaml \
		--repo-path $(REPOS_DIR)/mbedtls \
		--output-dir results/raw/coverity/mbedtls \
		--coverity-home $(COVERITY_HOME) \
		--checkers-config config/coverity_checkers.conf \
		--threads $(THREADS) \
		--skip-existing

dedup-mbedtls:
	$(PYTHON) deduplicator/dedup_findings.py \
		--ground-truth corpus/mbedtls/ground_truth.yaml \
		--codeql-results results/raw/codeql/mbedtls \
		--coverity-results results/raw/coverity/mbedtls \
		--output-dir results/deduplicated/mbedtls \
		--line-window $(LINE_WINDOW)

eval-mbedtls:
	$(PYTHON) evaluator/evaluate_instance.py \
		--ground-truth corpus/mbedtls/ground_truth.yaml \
		--dedup-dir results/deduplicated/mbedtls \
		--output results/metrics/mbedtls/instance_decisions.json

metrics-mbedtls: eval-mbedtls
	$(PYTHON) metrics/compute_metrics.py \
		--dedup-dir results/deduplicated/mbedtls \
		--output-dir results/metrics/mbedtls \
		--kloc $(MBED_KLOC) \
		--phase primary \
		--ground-truth corpus/mbedtls/ground_truth.yaml

# ---------------------------------------------------------------------------
# wolfSSL — Fase de Validación Externa
# ---------------------------------------------------------------------------
clone-wolfssl:
	@if [ ! -d "$(REPOS_DIR)/wolfssl" ]; then \
		git clone --quiet https://github.com/wolfSSL/wolfssl.git $(REPOS_DIR)/wolfssl; \
		echo "Clonado wolfSSL en $(REPOS_DIR)/wolfssl"; \
	else \
		echo "wolfSSL ya clonado."; \
	fi

run-wolfssl: validate clone-wolfssl
	$(PYTHON) runner/codeql/run_codeql.py \
		--ground-truth corpus/wolfssl/ground_truth.yaml \
		--repo-path $(REPOS_DIR)/wolfssl \
		--output-dir results/raw/codeql/wolfssl \
		--codeql-binary $(CODEQL_HOME)/codeql \
		--threads $(THREADS) \
		--skip-existing
	$(PYTHON) runner/coverity/run_coverity.py \
		--ground-truth corpus/wolfssl/ground_truth.yaml \
		--repo-path $(REPOS_DIR)/wolfssl \
		--output-dir results/raw/coverity/wolfssl \
		--coverity-home $(COVERITY_HOME) \
		--checkers-config config/coverity_checkers.conf \
		--threads $(THREADS) \
		--skip-existing
	$(PYTHON) deduplicator/dedup_findings.py \
		--ground-truth corpus/wolfssl/ground_truth.yaml \
		--codeql-results results/raw/codeql/wolfssl \
		--coverity-results results/raw/coverity/wolfssl \
		--output-dir results/deduplicated/wolfssl \
		--line-window $(LINE_WINDOW)
	$(PYTHON) evaluator/evaluate_instance.py \
		--ground-truth corpus/wolfssl/ground_truth.yaml \
		--dedup-dir results/deduplicated/wolfssl \
		--output results/metrics/wolfssl/instance_decisions.json
	$(PYTHON) metrics/compute_metrics.py \
		--dedup-dir results/deduplicated/wolfssl \
		--output-dir results/metrics/wolfssl \
		--kloc $(WOLFSSL_KLOC) \
		--phase validation \
		--ground-truth corpus/wolfssl/ground_truth.yaml

# ---------------------------------------------------------------------------
# Análisis cross-project y reporte final
# ---------------------------------------------------------------------------
cross-project: metrics-mbedtls
	$(PYTHON) scripts/cross_project_analysis.py \
		--primary-metrics results/metrics/mbedtls/instance_level_metrics.json \
		--validation-metrics results/metrics/wolfssl/instance_level_metrics.json \
		--output results/metrics/cross_project_consistency.json

report: cross-project
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@$(PYTHON) scripts/print_final_report.py \
		--primary-metrics results/metrics/mbedtls/benchmark_summary.json \
		--validation-metrics results/metrics/wolfssl/benchmark_summary.json \
		--cross results/metrics/cross_project_consistency.json
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	@echo "Informe también disponible en: results/metrics/"

# ---------------------------------------------------------------------------
# Pipeline completo
# ---------------------------------------------------------------------------
all: validate run-codeql-mbedtls run-coverity-mbedtls dedup-mbedtls \
     metrics-mbedtls run-wolfssl cross-project report
	@echo ""
	@echo "✓ Benchmark SAST completado."

# ---------------------------------------------------------------------------
# Limpieza
# ---------------------------------------------------------------------------
clean-results:
	@echo "Eliminando results/ ..."
	@rm -rf results/raw results/deduplicated results/metrics
	@mkdir -p results/raw/codeql results/raw/coverity results/deduplicated results/metrics
	@echo "✓ results/ limpiado (corpus/ y scripts/ intactos)."
