#!/usr/bin/env python3
"""
scripts/print_final_report.py
================================
Genera el informe final consolidado del benchmark SAST completo
(mbedTLS + wolfSSL + análisis cross-project) en Markdown para el
Job Summary de GitHub Actions.

Este es el documento que el tutor y el tribunal leen directamente
desde la interfaz de CI sin necesidad de descargar artefactos.

USO (en CI):
    python scripts/print_final_report.py \
        --primary-metrics results/metrics/mbedtls/benchmark_summary.json \
        --validation-metrics results/metrics/wolfssl/benchmark_summary.json \
        --cross results/metrics/cross_project_consistency.json \
        >> $GITHUB_STEP_SUMMARY
"""

import argparse
import json
from pathlib import Path


def pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def ci(t: list | None) -> str:
    if not t or len(t) < 2:
        return "—"
    return f"[{pct(t[0])}–{pct(t[1])}]"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--primary-metrics",    required=True)
    p.add_argument("--validation-metrics", required=True)
    p.add_argument("--cross",             required=True)
    args = p.parse_args()

    with open(args.primary_metrics)    as f: pm = json.load(f)
    with open(args.validation_metrics) as f: vm = json.load(f)
    with open(args.cross)              as f: cr = json.load(f)

    pil = pm.get("instance_level", {})
    pfl = pm.get("finding_level",  {})
    vil = vm.get("instance_level", {})
    vfl = vm.get("finding_level",  {})

    lines = []
    lines += [
        "# 📊 Benchmark SAST — Informe Final",
        "_POC-01 | CodeQL vs Coverity vs Unión sobre corpus C criptográfico_\n",

        "---",

        "## Resumen ejecutivo\n",
        "| Herramienta | Recall mbedTLS | CI 95% | Recall wolfSSL | CI 95% |",
        "|-------------|---------------|--------|---------------|--------|",
        f"| CodeQL          | **{pct(pil.get('Recall_CodeQL',0))}** | {ci(pil.get('Recall_CodeQL_CI95'))} | **{pct(vil.get('Recall_CodeQL',0))}** | {ci(vil.get('Recall_CodeQL_CI95'))} |",
        f"| Coverity        | **{pct(pil.get('Recall_Coverity',0))}** | {ci(pil.get('Recall_Coverity_CI95'))} | **{pct(vil.get('Recall_Coverity',0))}** | {ci(vil.get('Recall_Coverity_CI95'))} |",
        f"| **Unión**       | **{pct(pil.get('Recall_union',0))}** | {ci(pil.get('Recall_union_CI95'))} | **{pct(vil.get('Recall_union',0))}** | {ci(vil.get('Recall_union_CI95'))} |",
        "",

        "---",

        "## Ganancia marginal de la combinación\n",
        f"| Corpus | Ganancia marginal |",
        f"|--------|-------------------|",
        f"| mbedTLS (primary)    | `{pil.get('Marginal_gain_recall', 0):+.1%}` |",
        f"| wolfSSL (validation) | `{vil.get('Marginal_gain_recall', 0):+.1%}` |",
        "",
        f"> {pil.get('Marginal_gain_interpretation', '')}\n",

        "---",

        "## Desglose de verdaderos positivos (level: instancia)\n",
        "| Métrica              | mbedTLS | wolfSSL |",
        "|----------------------|---------|---------|",
        f"| N evaluable          | {pil.get('N_evaluable','?')} | {vil.get('N_evaluable','?')} |",
        f"| FN estructurales     | {pil.get('N_structural_fn','?')} | {vil.get('N_structural_fn','?')} |",
        f"| TP CodeQL            | {pil.get('TP_CodeQL','?')} | {vil.get('TP_CodeQL','?')} |",
        f"| TP Coverity          | {pil.get('TP_Coverity','?')} | {vil.get('TP_Coverity','?')} |",
        f"| TP overlap (ambas)   | {pil.get('TP_overlap','?')} | {vil.get('TP_overlap','?')} |",
        f"| TP único CodeQL      | {pil.get('TP_unique_CodeQL','?')} | {vil.get('TP_unique_CodeQL','?')} |",
        f"| TP único Coverity    | {pil.get('TP_unique_Coverity','?')} | {vil.get('TP_unique_Coverity','?')} |",
        f"| **TP unión**         | **{pil.get('TP_union','?')}** | **{vil.get('TP_union','?')}** |",
        "",

        "---",

        "## Volumen de ruido (level: finding deduplicado)\n",
        "| Métrica               | CodeQL mbedTLS | Coverity mbedTLS | CodeQL wolfSSL | Coverity wolfSSL |",
        "|-----------------------|----------------|------------------|----------------|------------------|",
        f"| Precision (finding)   | {pct(pfl.get('Precision_finding_CodeQL',0))} | {pct(pfl.get('Precision_finding_Coverity',0))} | {pct(vfl.get('Precision_finding_CodeQL',0))} | {pct(vfl.get('Precision_finding_Coverity',0))} |",
        f"| FP / KLOC             | {pfl.get('FP_per_KLOC_CodeQL','?')} | {pfl.get('FP_per_KLOC_Coverity','?')} | {vfl.get('FP_per_KLOC_CodeQL','?')} | {vfl.get('FP_per_KLOC_Coverity','?')} |",
        f"| Revisión manual       | {pfl.get('review_cost_hours_CodeQL','?')} h | {pfl.get('review_cost_hours_Coverity','?')} h | {vfl.get('review_cost_hours_CodeQL','?')} h | {vfl.get('review_cost_hours_Coverity','?')} h |",
        "",

        "---",

        "## Consistencia cross-project\n",
        f"| Corpus | Δ(CodeQL − Coverity) |",
        f"|--------|----------------------|",
        f"| mbedTLS    | `{cr.get('Recall_diff_CQ_minus_CV_primary', 0):+.4f}` |",
        f"| wolfSSL    | `{cr.get('Recall_diff_CQ_minus_CV_validation', 0):+.4f}` |",
        "",
        f"**Dirección consistente:** {'✅ SÍ' if cr.get('direction_consistent') else '❌ NO'}\n",
        f"> {cr.get('direction_interpretation', '')}\n",
        "",
        f"> ⚠️ {cr.get('statistical_caveat', '')}\n",

        "---",

        "## Artefactos generados\n",
        "| Artefacto | Descripción |",
        "|-----------|-------------|",
        "| `codeql-mbedtls-sarif` | SARIF por CVE (V + S), CodeQL sobre mbedTLS |",
        "| `coverity-mbedtls-json` | JSON v8 por CVE (V + S), Coverity sobre mbedTLS |",
        "| `metrics-mbedtls` | Métricas completas (instance + finding level) |",
        "| `benchmark-final-report` | Este informe + análisis cross-project |",
        "",
        "_Este benchmark corresponde a POC-01. La integración en pipeline (CAP-02) depende de las conclusiones aquí documentadas._",
    ]

    print("\n".join(lines))


if __name__ == "__main__":
    main()
