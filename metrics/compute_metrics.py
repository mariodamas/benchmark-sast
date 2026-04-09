#!/usr/bin/env python3
"""
metrics/compute_metrics.py
===========================
Calcula las métricas del benchmark SAST en dos planos independientes:

PLANO 1 — Instance-level (métrica principal)
  Unidad: cada CVE del ground truth es una instancia.
  Pregunta: ¿ha detectado o no ha detectado la herramienta la vulnerabilidad?
  Resultado: recall, precision, F1 por herramienta y por la unión.

PLANO 2 — Finding-level (métrica secundaria: volumen de ruido)
  Unidad: cada finding deduplicado generado por la herramienta.
  Pregunta: ¿cuánto ruido genera? ¿Cuál es el FP rate real?
  Resultado: FP/KLOC, FP/CVE evaluado, coste de revisión estimado.

MÉTRICAS CLAVE DEL BENCHMARK (las que responden a la pregunta del TFG):
  - Recall_CodeQL   = TP_CodeQL / N_evaluable
  - Recall_Coverity = TP_Coverity / N_evaluable
  - Recall_union    = TP_union / N_evaluable
    → Marginal_gain = Recall_union - max(Recall_CodeQL, Recall_Coverity)
    → Responde: "¿Coverity sobre CodeQL aporta cobertura real o solo coste?"

USO:
    python compute_metrics.py \
        --dedup-dir ../results/deduplicated/mbedtls \
        --output-dir ../results/metrics/mbedtls \
        --kloc 60 \
        [--phase primary|validation]
"""

import argparse
import json
import logging
import math
import sys
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

REVIEW_COST_MINUTES_PER_FINDING = 15  # Estimación conservadora de revisión manual


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--dedup-dir", required=True,
                   help="Directorio con los JSON deduplicados por CVE")
    p.add_argument("--output-dir", required=True,
                   help="Directorio de salida para métricas")
    p.add_argument("--kloc", type=float, required=True,
                   help="Tamaño del proyecto en KLOC (kilolines of code)")
    p.add_argument("--phase", choices=["primary", "validation"], default="primary")
    p.add_argument("--ground-truth", required=False,
                   help="Ruta al ground_truth.yaml (para metadatos adicionales)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Helpers estadísticos
# ---------------------------------------------------------------------------

def safe_div(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator > 0 else 0.0


def f1(precision: float, recall: float) -> float:
    return safe_div(2 * precision * recall, precision + recall)


def wilson_ci_95(k: int, n: int) -> tuple[float, float]:
    """
    Intervalo de confianza de Wilson al 95% para una proporción k/n.
    Más robusto que el IC normal para muestras pequeñas (lo que tenemos).
    Retorna (lower, upper).
    """
    if n == 0:
        return (0.0, 1.0)
    z = 1.96
    p_hat = k / n
    denom = 1 + z**2 / n
    centre = (p_hat + z**2 / (2 * n)) / denom
    margin = (z * math.sqrt(p_hat * (1 - p_hat) / n + z**2 / (4 * n**2))) / denom
    return (round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4))


# ---------------------------------------------------------------------------
# Carga de datos deduplicados
# ---------------------------------------------------------------------------

def load_dedup_instances(dedup_dir: str) -> list[dict]:
    instances = []
    for json_file in sorted(Path(dedup_dir).glob("*_dedup.json")):
        if json_file.name == "summary_dedup.json":
            continue
        with open(json_file) as f:
            instances.append(json.load(f))
    return instances


# ---------------------------------------------------------------------------
# PLANO 1: Instance-level metrics
# ---------------------------------------------------------------------------

def compute_instance_level_metrics(instances: list[dict]) -> dict:
    """
    Para cada instancia, una herramienta "detecta" si tiene ≥1 TP_V_DISAPPEARS
    deduplicado en el archivo afectado.
    Instancias structural_fn se excluyen del denominador.
    """
    evaluable = [i for i in instances if not i.get("structural_fn")]
    structural_fns = [i for i in instances if i.get("structural_fn")]

    N = len(evaluable)
    if N == 0:
        log.warning("No hay instancias evaluables (todas son FN estructurales).")
        return {}

    # Detectado por herramienta X si TP_V_DISAPPEARS_X ≥ 1
    detected_cq = [i for i in evaluable if i.get("TP_V_DISAPPEARS_codeql", 0) >= 1]
    detected_cv = [i for i in evaluable if i.get("TP_V_DISAPPEARS_coverity", 0) >= 1]
    # Unión: detectado por al menos una herramienta
    detected_union = [i for i in evaluable if i.get("TP_union", 0) >= 1]
    # Overlap: detectado por ambas
    detected_overlap = [i for i in evaluable
                        if i.get("TP_V_DISAPPEARS_codeql", 0) >= 1
                        and i.get("TP_V_DISAPPEARS_coverity", 0) >= 1]
    # Únicos por herramienta
    unique_cq = [i for i in evaluable
                 if i.get("TP_V_DISAPPEARS_codeql", 0) >= 1
                 and i.get("TP_V_DISAPPEARS_coverity", 0) == 0]
    unique_cv = [i for i in evaluable
                 if i.get("TP_V_DISAPPEARS_coverity", 0) >= 1
                 and i.get("TP_V_DISAPPEARS_codeql", 0) == 0]

    # FN por herramienta
    fn_cq = [i for i in evaluable if i.get("TP_V_DISAPPEARS_codeql", 0) == 0]
    fn_cv = [i for i in evaluable if i.get("TP_V_DISAPPEARS_coverity", 0) == 0]

    # Recall (métrica principal)
    recall_cq    = safe_div(len(detected_cq), N)
    recall_cv    = safe_div(len(detected_cv), N)
    recall_union = safe_div(len(detected_union), N)
    marginal_gain = round(recall_union - max(recall_cq, recall_cv), 4)

    # Precision instance-level:
    # Instancias con ≥1 TP / instancias analizadas
    # (nota: precision finding-level está en PLANO 2)
    precision_cq = safe_div(
        len(detected_cq),
        len([i for i in evaluable if i.get("findings_dedup_V_codeql", 0) > 0])
    )
    precision_cv = safe_div(
        len(detected_cv),
        len([i for i in evaluable if i.get("findings_dedup_V_coverity", 0) > 0])
    )

    # Wilson CIs para recall
    recall_cq_ci    = wilson_ci_95(len(detected_cq), N)
    recall_cv_ci    = wilson_ci_95(len(detected_cv), N)
    recall_union_ci = wilson_ci_95(len(detected_union), N)

    metrics = {
        "phase": "instance_level",
        "N_total_corpus":     len(instances),
        "N_structural_fn":    len(structural_fns),
        "N_evaluable":        N,

        # --- Counts ---
        "TP_CodeQL":          len(detected_cq),
        "TP_Coverity":        len(detected_cv),
        "TP_overlap":         len(detected_overlap),
        "TP_unique_CodeQL":   len(unique_cq),
        "TP_unique_Coverity": len(unique_cv),
        "TP_union":           len(detected_union),
        "FN_CodeQL":          len(fn_cq),
        "FN_Coverity":        len(fn_cv),

        # --- Recall (LA métrica central) ---
        "Recall_CodeQL":      recall_cq,
        "Recall_Coverity":    recall_cv,
        "Recall_union":       recall_union,
        "Recall_CodeQL_CI95":  recall_cq_ci,
        "Recall_Coverity_CI95": recall_cv_ci,
        "Recall_union_CI95":  recall_union_ci,

        # --- Ganancia marginal ---
        "Marginal_gain_recall": marginal_gain,
        "Marginal_gain_interpretation": (
            f"Coverity añade {marginal_gain:.1%} de cobertura adicional sobre CodeQL"
            if marginal_gain > 0
            else "Coverity no añade cobertura sobre CodeQL a nivel de instancia"
        ),

        # --- Precision instance-level ---
        "Precision_instance_CodeQL":   precision_cq,
        "Precision_instance_Coverity": precision_cv,
        "F1_instance_CodeQL":          f1(precision_cq, recall_cq),
        "F1_instance_Coverity":        f1(precision_cv, recall_cv),

        # --- FN estructurales (documentados, no penalizados) ---
        "structural_fns": [
            {"cve": i["cve_id"], "cwe": i["cwe"]}
            for i in structural_fns
        ],

        # --- CVEs por herramienta ---
        "CVEs_detected_CodeQL":   [i["cve_id"] for i in detected_cq],
        "CVEs_detected_Coverity": [i["cve_id"] for i in detected_cv],
        "CVEs_unique_CodeQL":     [i["cve_id"] for i in unique_cq],
        "CVEs_unique_Coverity":   [i["cve_id"] for i in unique_cv],
        "CVEs_missed_CodeQL":     [i["cve_id"] for i in fn_cq],
        "CVEs_missed_Coverity":   [i["cve_id"] for i in fn_cv],
    }
    return metrics


# ---------------------------------------------------------------------------
# PLANO 2: Finding-level metrics (ruido y coste de revisión)
# ---------------------------------------------------------------------------

def compute_finding_level_metrics(instances: list[dict], kloc: float) -> dict:
    """
    Métricas de volumen de ruido a nivel de finding deduplicado.
    Estas métricas NO entran en el cálculo de recall/precision principal;
    son secundarias y miden el coste operativo de cada herramienta.
    """
    evaluable = [i for i in instances if not i.get("structural_fn")]

    total_findings_cq_v = sum(i.get("findings_dedup_V_codeql", 0) for i in evaluable)
    total_findings_cv_v = sum(i.get("findings_dedup_V_coverity", 0) for i in evaluable)

    total_tp_cq = sum(i.get("TP_V_DISAPPEARS_codeql", 0) for i in evaluable)
    total_tp_cv = sum(i.get("TP_V_DISAPPEARS_coverity", 0) for i in evaluable)
    total_fp_cq = sum(i.get("FP_PERSISTS_codeql", 0) for i in evaluable)
    total_fp_cv = sum(i.get("FP_PERSISTS_coverity", 0) for i in evaluable)
    total_fp_union = sum(i.get("FP_union", 0) for i in evaluable)
    total_tp_union = sum(i.get("TP_union", 0) for i in evaluable)

    # Precision finding-level (deduplicada)
    precision_finding_cq = safe_div(total_tp_cq, total_findings_cq_v)
    precision_finding_cv = safe_div(total_tp_cv, total_findings_cv_v)
    total_union_findings = total_tp_union + total_fp_union
    precision_finding_union = safe_div(total_tp_union, total_union_findings)

    # FP por KLOC (métrica estándar en literatura SAST)
    fp_per_kloc_cq    = safe_div(total_fp_cq, kloc)
    fp_per_kloc_cv    = safe_div(total_fp_cv, kloc)
    fp_per_kloc_union = safe_div(total_fp_union, kloc)

    # FP por CVE evaluado
    N = len(evaluable)
    fp_per_cve_cq    = safe_div(total_fp_cq, N)
    fp_per_cve_cv    = safe_div(total_fp_cv, N)

    # Coste de revisión manual estimado (minutos)
    review_cost_cq    = (total_findings_cq_v) * REVIEW_COST_MINUTES_PER_FINDING
    review_cost_cv    = (total_findings_cv_v) * REVIEW_COST_MINUTES_PER_FINDING
    review_cost_union = (total_union_findings) * REVIEW_COST_MINUTES_PER_FINDING

    return {
        "phase": "finding_level",
        "kloc": kloc,
        "review_cost_minutes_per_finding": REVIEW_COST_MINUTES_PER_FINDING,

        # --- Totales de findings deduplicados ---
        "total_findings_dedup_V_CodeQL":   total_findings_cq_v,
        "total_findings_dedup_V_Coverity": total_findings_cv_v,
        "total_TP_findings_CodeQL":   total_tp_cq,
        "total_TP_findings_Coverity": total_tp_cv,
        "total_FP_findings_CodeQL":   total_fp_cq,
        "total_FP_findings_Coverity": total_fp_cv,
        "total_FP_findings_union":    total_fp_union,

        # --- Precision finding-level ---
        "Precision_finding_CodeQL":   precision_finding_cq,
        "Precision_finding_Coverity": precision_finding_cv,
        "Precision_finding_union":    precision_finding_union,

        # --- FP rate normalizado ---
        "FP_per_KLOC_CodeQL":   fp_per_kloc_cq,
        "FP_per_KLOC_Coverity": fp_per_kloc_cv,
        "FP_per_KLOC_union":    fp_per_kloc_union,
        "FP_per_CVE_CodeQL":    fp_per_cve_cq,
        "FP_per_CVE_Coverity":  fp_per_cve_cv,

        # --- Coste de revisión manual estimado ---
        "review_cost_minutes_CodeQL":   review_cost_cq,
        "review_cost_minutes_Coverity": review_cost_cv,
        "review_cost_minutes_union":    review_cost_union,
        "review_cost_hours_CodeQL":     round(review_cost_cq / 60, 1),
        "review_cost_hours_Coverity":   round(review_cost_cv / 60, 1),
        "review_cost_hours_union":      round(review_cost_union / 60, 1),
    }


# ---------------------------------------------------------------------------
# Comparación cross-project (mbedTLS vs wolfSSL)
# ---------------------------------------------------------------------------

def compute_cross_project_consistency(
    metrics_primary: dict, metrics_validation: dict
) -> dict:
    """
    Calcula si las diferencias de recall entre herramientas son consistentes
    entre mbedTLS (primary) y wolfSSL (validation).
    Si la diferencia Recall_CodeQL - Recall_Coverity tiene el mismo signo
    en ambos proyectos, la conclusión es robusta al corpus.
    """
    diff_primary    = round(
        metrics_primary.get("Recall_CodeQL", 0) - metrics_primary.get("Recall_Coverity", 0), 4
    )
    diff_validation = round(
        metrics_validation.get("Recall_CodeQL", 0) - metrics_validation.get("Recall_Coverity", 0), 4
    )
    consistent = (diff_primary >= 0) == (diff_validation >= 0)

    return {
        "Recall_diff_CodeQL_minus_Coverity_primary":    diff_primary,
        "Recall_diff_CodeQL_minus_Coverity_validation": diff_validation,
        "direction_consistent": consistent,
        "interpretation": (
            "La diferencia entre CodeQL y Coverity es consistente entre mbedTLS y wolfSSL. "
            "La conclusión sobre complementariedad es robusta al corpus."
            if consistent else
            "La diferencia entre herramientas invierte su signo entre corpus. "
            "La complementariedad puede depender del código analizado, no de la herramienta."
        ),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    instances = load_dedup_instances(args.dedup_dir)
    if not instances:
        log.error(f"No se encontraron instancias deduplicadas en {args.dedup_dir}")
        sys.exit(1)

    log.info(f"Instancias cargadas: {len(instances)}")

    # PLANO 1
    log.info("\n--- PLANO 1: Instance-level metrics ---")
    il_metrics = compute_instance_level_metrics(instances)
    log.info(f"  N_evaluable:     {il_metrics.get('N_evaluable')}")
    log.info(f"  Recall CodeQL:   {il_metrics.get('Recall_CodeQL'):.1%}  CI95={il_metrics.get('Recall_CodeQL_CI95')}")
    log.info(f"  Recall Coverity: {il_metrics.get('Recall_Coverity'):.1%}  CI95={il_metrics.get('Recall_Coverity_CI95')}")
    log.info(f"  Recall union:    {il_metrics.get('Recall_union'):.1%}  CI95={il_metrics.get('Recall_union_CI95')}")
    log.info(f"  Marginal gain:   {il_metrics.get('Marginal_gain_recall'):.1%}")
    log.info(f"  TP_unique_CodeQL:   {il_metrics.get('TP_unique_CodeQL')}")
    log.info(f"  TP_unique_Coverity: {il_metrics.get('TP_unique_Coverity')}")

    il_path = Path(args.output_dir) / "instance_level_metrics.json"
    with open(il_path, "w") as f:
        json.dump(il_metrics, f, indent=2)

    # PLANO 2
    log.info("\n--- PLANO 2: Finding-level metrics ---")
    fl_metrics = compute_finding_level_metrics(instances, args.kloc)
    log.info(f"  FP/KLOC CodeQL:   {fl_metrics.get('FP_per_KLOC_CodeQL')}")
    log.info(f"  FP/KLOC Coverity: {fl_metrics.get('FP_per_KLOC_Coverity')}")
    log.info(f"  FP/KLOC union:    {fl_metrics.get('FP_per_KLOC_union')}")
    log.info(f"  Revisión manual CodeQL:   {fl_metrics.get('review_cost_hours_CodeQL')} h")
    log.info(f"  Revisión manual Coverity: {fl_metrics.get('review_cost_hours_Coverity')} h")
    log.info(f"  Revisión manual union:    {fl_metrics.get('review_cost_hours_union')} h")

    fl_path = Path(args.output_dir) / "finding_level_metrics.json"
    with open(fl_path, "w") as f:
        json.dump(fl_metrics, f, indent=2)

    # Resumen ejecutivo
    summary = {
        "project":        args.phase,
        "kloc":           args.kloc,
        "instance_level": il_metrics,
        "finding_level":  fl_metrics,
    }
    summary_path = Path(args.output_dir) / "benchmark_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    log.info(f"\n✓ Métricas calculadas. Resumen: {summary_path}")
    log.info(f"\n{'='*60}")
    log.info("CONCLUSIÓN PRINCIPAL DEL BENCHMARK:")
    log.info(f"  {il_metrics.get('Marginal_gain_interpretation')}")
    log.info(f"{'='*60}")


if __name__ == "__main__":
    main()
