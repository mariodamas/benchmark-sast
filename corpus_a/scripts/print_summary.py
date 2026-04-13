#!/usr/bin/env python3
"""
scripts/print_summary.py
==========================
Renderiza un resumen Markdown del benchmark para el Job Summary de
GitHub Actions (se añade a $GITHUB_STEP_SUMMARY con >>).

USO (en CI):
    python scripts/print_summary.py \
        --metrics results/metrics/mbedtls/benchmark_summary.json \
        >> $GITHUB_STEP_SUMMARY

USO (local, inspección rápida):
    python scripts/print_summary.py \
        --metrics results/metrics/mbedtls/benchmark_summary.json
"""

import argparse
import json
import sys
from pathlib import Path


def pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def ci_str(ci: list | None) -> str:
    if not ci or len(ci) < 2:
        return ""
    return f"[{pct(ci[0])} – {pct(ci[1])}]"


def bar(v: float, width: int = 20) -> str:
    filled = int(round(v * width))
    return "█" * filled + "░" * (width - filled)


def render_instance_level(il: dict) -> str:
    lines = []
    n = il.get("N_evaluable", 0)
    n_sfn = il.get("N_structural_fn", 0)

    lines.append("## Plano 1 — Instance-level metrics (métrica principal)\n")
    lines.append(f"| Dimensión | Valor |")
    lines.append(f"|-----------|-------|")
    lines.append(f"| Instancias corpus total | {il.get('N_total_corpus', '?')} |")
    lines.append(f"| FN estructurales (excluidos) | {n_sfn} |")
    lines.append(f"| **Instancias evaluables (N)** | **{n}** |")
    lines.append("")

    lines.append("### Recall por herramienta\n")
    lines.append("| Herramienta | Recall | CI 95% | Barra |")
    lines.append("|-------------|--------|--------|-------|")

    r_cq = il.get("Recall_CodeQL", 0)
    r_cv = il.get("Recall_Coverity", 0)
    r_un = il.get("Recall_union", 0)
    mg   = il.get("Marginal_gain_recall", 0)

    lines.append(f"| CodeQL   | **{pct(r_cq)}** | {ci_str(il.get('Recall_CodeQL_CI95'))} | `{bar(r_cq)}` |")
    lines.append(f"| Coverity | **{pct(r_cv)}** | {ci_str(il.get('Recall_Coverity_CI95'))} | `{bar(r_cv)}` |")
    lines.append(f"| **Unión**    | **{pct(r_un)}** | {ci_str(il.get('Recall_union_CI95'))} | `{bar(r_un)}` |")
    lines.append("")

    mg_sign = "+" if mg >= 0 else ""
    lines.append(f"**Ganancia marginal (Recall_union − max):** `{mg_sign}{pct(mg)}`\n")
    lines.append(f"> {il.get('Marginal_gain_interpretation', '')}\n")

    lines.append("### Verdaderos Positivos (deduplicados, nivel instancia)\n")
    lines.append("| Métrica | Valor |")
    lines.append("|---------|-------|")
    lines.append(f"| TP_CodeQL                | {il.get('TP_CodeQL', 0)} |")
    lines.append(f"| TP_Coverity              | {il.get('TP_Coverity', 0)} |")
    lines.append(f"| TP_overlap (ambas)       | {il.get('TP_overlap', 0)} |")
    lines.append(f"| TP_unique_CodeQL         | {il.get('TP_unique_CodeQL', 0)} |")
    lines.append(f"| TP_unique_Coverity       | {il.get('TP_unique_Coverity', 0)} |")
    lines.append(f"| **TP_union**             | **{il.get('TP_union', 0)}** |")
    lines.append(f"| FN_CodeQL                | {il.get('FN_CodeQL', 0)} |")
    lines.append(f"| FN_Coverity              | {il.get('FN_Coverity', 0)} |")
    lines.append("")

    if il.get("CVEs_unique_CodeQL"):
        lines.append(f"**CVEs únicos de CodeQL:** `{'`, `'.join(il['CVEs_unique_CodeQL'])}`\n")
    if il.get("CVEs_unique_Coverity"):
        lines.append(f"**CVEs únicos de Coverity:** `{'`, `'.join(il['CVEs_unique_Coverity'])}`\n")
    if il.get("CVEs_missed_CodeQL"):
        lines.append(f"**CVEs perdidos por CodeQL:** `{'`, `'.join(il['CVEs_missed_CodeQL'])}`\n")
    if il.get("CVEs_missed_Coverity"):
        lines.append(f"**CVEs perdidos por Coverity:** `{'`, `'.join(il['CVEs_missed_Coverity'])}`\n")

    if il.get("structural_fns"):
        lines.append("### FN Estructurales (excluidos del cálculo)\n")
        lines.append("| CVE | CWE | Razón |")
        lines.append("|-----|-----|-------|")
        for sfn in il["structural_fns"]:
            lines.append(f"| {sfn['cve']} | {sfn['cwe']} | Timing side-channel — no detectable por SAST |")
        lines.append("")

    return "\n".join(lines)


def render_finding_level(fl: dict) -> str:
    lines = []
    lines.append("## Plano 2 — Finding-level metrics (ruido y coste de revisión)\n")
    lines.append(f"Tamaño del proyecto: **{fl.get('kloc', '?')} KLOC**\n")

    lines.append("| Métrica | CodeQL | Coverity | Unión |")
    lines.append("|---------|--------|----------|-------|")
    lines.append(f"| Findings deduplicados (V) | {fl.get('total_findings_dedup_V_CodeQL', '?')} | {fl.get('total_findings_dedup_V_Coverity', '?')} | — |")
    lines.append(f"| TP findings               | {fl.get('total_TP_findings_CodeQL', '?')} | {fl.get('total_TP_findings_Coverity', '?')} | {fl.get('total_TP_findings_CodeQL', 0) + fl.get('total_TP_findings_Coverity', 0)} |")
    lines.append(f"| FP findings               | {fl.get('total_FP_findings_CodeQL', '?')} | {fl.get('total_FP_findings_Coverity', '?')} | {fl.get('total_FP_findings_union', '?')} |")
    lines.append(f"| Precision (finding)       | {pct(fl.get('Precision_finding_CodeQL', 0))} | {pct(fl.get('Precision_finding_Coverity', 0))} | {pct(fl.get('Precision_finding_union', 0))} |")
    lines.append(f"| FP / KLOC                 | {fl.get('FP_per_KLOC_CodeQL', '?')} | {fl.get('FP_per_KLOC_Coverity', '?')} | {fl.get('FP_per_KLOC_union', '?')} |")
    lines.append(f"| FP / CVE evaluado         | {fl.get('FP_per_CVE_CodeQL', '?')} | {fl.get('FP_per_CVE_Coverity', '?')} | — |")
    lines.append(f"| Coste revisión manual     | {fl.get('review_cost_hours_CodeQL', '?')} h | {fl.get('review_cost_hours_Coverity', '?')} h | {fl.get('review_cost_hours_union', '?')} h |")
    lines.append("")
    lines.append(f"> Estimación: {fl.get('review_cost_minutes_per_finding', 15)} min de revisión por finding deduplicado.\n")

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--metrics", required=True, help="Ruta a benchmark_summary.json")
    args = p.parse_args()

    with open(args.metrics) as f:
        summary = json.load(f)

    phase   = summary.get("project", "primary")
    il      = summary.get("instance_level", {})
    fl      = summary.get("finding_level", {})

    label = "mbedTLS (Corpus Principal)" if phase == "primary" else "wolfSSL (Corpus de Validación)"

    out = []
    out.append(f"# Benchmark SAST — {label}\n")
    out.append(f"_POC-01 | CodeQL vs Coverity vs Unión | Metodología: ground truth por CVE con versión V/S_\n")
    out.append("")
    out.append(render_instance_level(il))
    out.append(render_finding_level(fl))

    print("\n".join(out))


if __name__ == "__main__":
    main()
