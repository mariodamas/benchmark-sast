#!/usr/bin/env python3
"""
scripts/cross_project_analysis.py
===================================
Compara la consistencia de las diferencias entre herramientas
entre el corpus primary (mbedTLS) y el corpus de validación (wolfSSL).

Pregunta central:
  ¿La diferencia Recall_CodeQL - Recall_Coverity tiene el mismo signo
  en mbedTLS que en wolfSSL?
  → Si sí: la conclusión sobre complementariedad es robusta al corpus.
  → Si no: la complementariedad puede ser un artefacto del código analizado.

Esta es exactamente la validez externa que wolfSSL aporta al benchmark.
"""

import argparse
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--primary-metrics", required=True)
    p.add_argument("--validation-metrics", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    with open(args.primary_metrics) as f:
        primary = json.load(f)
    with open(args.validation_metrics) as f:
        validation = json.load(f)

    def get(d, key, default=0.0):
        return d.get(key, default)

    # Diferencias de recall por herramienta
    diff_p = round(get(primary, "Recall_CodeQL") - get(primary, "Recall_Coverity"), 4)
    diff_v = round(get(validation, "Recall_CodeQL") - get(validation, "Recall_Coverity"), 4)
    consistent = (diff_p >= 0) == (diff_v >= 0)

    # Ganancia marginal en ambos corpus
    mg_p = get(primary, "Marginal_gain_recall")
    mg_v = get(validation, "Marginal_gain_recall")
    mg_consistent = (mg_p >= 0) == (mg_v >= 0)

    # Recall union: ¿es la ganancia real en ambos corpus?
    ru_p = get(primary, "Recall_union")
    ru_v = get(validation, "Recall_union")

    result = {
        "primary_project":    "mbedtls",
        "validation_project": "wolfssl",

        # Recalls individuales
        "Recall_CodeQL_primary":      get(primary, "Recall_CodeQL"),
        "Recall_Coverity_primary":    get(primary, "Recall_Coverity"),
        "Recall_union_primary":       ru_p,
        "Recall_CodeQL_validation":   get(validation, "Recall_CodeQL"),
        "Recall_Coverity_validation": get(validation, "Recall_Coverity"),
        "Recall_union_validation":    ru_v,

        # Diferencias
        "Recall_diff_CQ_minus_CV_primary":    diff_p,
        "Recall_diff_CQ_minus_CV_validation": diff_v,
        "direction_consistent": consistent,

        # Ganancia marginal
        "Marginal_gain_primary":    mg_p,
        "Marginal_gain_validation": mg_v,
        "marginal_gain_consistent": mg_consistent,

        # TP únicos (¿qué herramienta aporta más en cada corpus?)
        "TP_unique_CodeQL_primary":    get(primary, "TP_unique_CodeQL"),
        "TP_unique_Coverity_primary":  get(primary, "TP_unique_Coverity"),
        "TP_unique_CodeQL_validation": get(validation, "TP_unique_CodeQL"),
        "TP_unique_Coverity_validation": get(validation, "TP_unique_Coverity"),

        # Interpretaciones
        "direction_interpretation": (
            "ROBUSTO: La diferencia de recall entre CodeQL y Coverity tiene el mismo "
            "signo en mbedTLS y wolfSSL. La conclusión sobre complementariedad no depende "
            "del corpus analizado."
            if consistent else
            "FRÁGIL: La diferencia de recall invierte su signo entre mbedTLS y wolfSSL. "
            "La complementariedad semántica puede ser un artefacto del código específico "
            "de mbedTLS, no una propiedad general de las herramientas sobre C criptográfico."
        ),
        "marginal_gain_interpretation": (
            "CONSISTENTE: La ganancia marginal de usar ambas herramientas es positiva "
            "en ambos corpus. La unión justifica el coste."
            if mg_consistent and mg_p > 0 and mg_v > 0 else
            "INCONSISTENTE o NEGATIVA: La ganancia marginal no se confirma en validación. "
            "Revisar si el corpus de validación tiene suficiente tamaño muestral."
        ),

        # Aviso estadístico sobre el tamaño muestral
        "statistical_caveat": (
            "AVISO: Con N_evaluable pequeño (< 10 instancias por corpus), los intervalos "
            "de confianza de Wilson son amplios. Las conclusiones son indicativas, "
            "no estadísticamente definitivas. Se recomienda documentar esto explícitamente "
            "en el TFG y citar el límite de tamaño de muestra como trabajo futuro."
        ),
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print("\n" + "="*60)
    print("ANÁLISIS CROSS-PROJECT")
    print("="*60)
    print(f"  mbedTLS  → Recall CodeQL={result['Recall_CodeQL_primary']:.1%} "
          f"Coverity={result['Recall_Coverity_primary']:.1%} "
          f"union={result['Recall_union_primary']:.1%}")
    print(f"  wolfSSL  → Recall CodeQL={result['Recall_CodeQL_validation']:.1%} "
          f"Coverity={result['Recall_Coverity_validation']:.1%} "
          f"union={result['Recall_union_validation']:.1%}")
    print(f"\n  Dirección consistente: {'SÍ ✓' if consistent else 'NO ✗'}")
    print(f"  {result['direction_interpretation']}")
    print(f"\n  {result['statistical_caveat']}")
    print("="*60)


if __name__ == "__main__":
    main()
