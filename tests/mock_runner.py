#!/usr/bin/env python3
"""
tests/mock_runner.py
=====================
Genera datos sintéticos de SARIF (CodeQL) y JSON v8 (Coverity) para
ejecutar el pipeline completo sin necesidad de tener CodeQL ni Coverity
instalados. Útil para:
  - Verificar que el pipeline de deduplicación y métricas funciona end-to-end
  - Testear casos límite (TP_unique, FP_persists, structural_fn)
  - Desarrollar scripts de reporte antes de tener resultados reales

ESCENARIO DE TEST DEFINIDO:
  mbedTLS — 5 instancias evaluables:

  CVE-2021-43666 (null-deref):
    CodeQL V: 1 finding en dhm.c línea 150 → desaparece en S → TP_CodeQL
    Coverity V: 1 finding en dhm.c línea 148 → desaparece en S → TP_Coverity
    → TP_overlap (ambas detectan)

  CVE-2020-36421 (integer-overflow):
    CodeQL V: 1 finding en bignum.c línea 200 → desaparece en S → TP_CodeQL
    Coverity V: 0 findings relevantes → FN_Coverity
    → TP_unique_CodeQL

  CVE-2022-46392 (buffer-overflow, OOB read):
    CodeQL V: 0 findings relevantes → FN_CodeQL
    Coverity V: 2 findings en x509.c (mismo defecto, checker duplicado) → TP_Coverity
    → TP_unique_Coverity

  CVE-2022-46393 (buffer-overflow, heap):
    CodeQL V: 3 findings en asn1parse.c (2 duplicados en líneas ±5) → 1 TP_CodeQL único
    Coverity V: 1 finding en asn1parse.c → TP_Coverity
    CodeQL S: 1 finding persiste (FP) → FP_CodeQL
    → TP_overlap + FP_CodeQL

  CVE-2023-43615 (use-after-free):
    CodeQL V: 1 finding en ssl_tls13_client.c → TP_CodeQL
    Coverity V: 1 finding en ssl_tls13_client.c → TP_Coverity
    → TP_overlap

  Esperado:
    TP_CodeQL   = 4 instancias
    TP_Coverity = 4 instancias
    TP_overlap  = 3 instancias
    TP_unique_CodeQL   = 1 (CVE-2020-36421)
    TP_unique_Coverity = 1 (CVE-2022-46392)
    TP_union    = 5 instancias → Recall_union = 5/5 = 1.0
    FN_CodeQL   = 1 (CVE-2022-46392)
    FN_Coverity = 1 (CVE-2020-36421)
    Marginal_gain = 1.0 - max(0.8, 0.8) = 0.2

USO:
    python tests/mock_runner.py \
        --output-dir /tmp/mock_results \
        [--project mbedtls]
"""

import argparse
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ---------------------------------------------------------------------------
# Generadores de SARIF (CodeQL)
# ---------------------------------------------------------------------------

def make_sarif(findings: list[dict], analysis_seconds: float = 42.0) -> dict:
    """
    Genera un SARIF 2.1.0 mínimo pero sintácticamente correcto.
    findings: lista de dicts con rule_id, uri, line, message.
    """
    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule_id"],
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"library/{f['uri']}", "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f["line"], "startColumn": 1},
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "properties": {"benchmark_analysis_seconds": analysis_seconds},
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "version": "2.16.5",
                    "rules": [
                        {"id": "cpp/nullptr-dereference",      "name": "NullPointerDereference"},
                        {"id": "cpp/integer-overflow-tainted", "name": "IntegerOverflowTainted"},
                        {"id": "cpp/overflow-buffer",          "name": "BufferOverflow"},
                        {"id": "cpp/use-after-free",           "name": "UseAfterFree"},
                        {"id": "cpp/overrunning-write",        "name": "OverrunningWrite"},
                    ],
                }
            },
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------
# Generadores de JSON v8 (Coverity)
# ---------------------------------------------------------------------------

def make_coverity_json(findings: list[dict]) -> dict:
    """
    Genera un JSON v8 de Coverity mínimo pero parseable por el deduplicador.
    findings: lista de dicts con checker, file_path, line, cwe, message.
    """
    issues = []
    for i, f in enumerate(findings):
        issues.append({
            "mergeKey": f"mock-{i:04d}",
            "checkerName": f["checker"],
            "mainEventFilePathname": f"/home/runner/repos/mbedtls/library/{f['file_path']}",
            "mainEventLineNumber": f["line"],
            "impact": f.get("impact", "High"),
            "checkerProperties": {
                "cweCategory": f.get("cwe", ""),
                "subcategoryShortDescription": f.get("message", ""),
                "subcategoryLocalEffect": "Potential security vulnerability",
            },
        })
    return {"issues": issues}


# ---------------------------------------------------------------------------
# Escenario de test: mbedTLS
# ---------------------------------------------------------------------------

MOCK_SCENARIOS = {
    # -----------------------------------------------------------------------
    # CVE-2021-43666 — null-deref en dhm.c
    # Ambas herramientas detectan → TP_overlap
    # -----------------------------------------------------------------------
    "CVE-2021-43666": {
        "codeql": {
            "V": make_sarif([{
                "rule_id": "cpp/nullptr-dereference",
                "uri": "dhm.c",
                "line": 150,
                "message": "Potential null pointer dereference of mbedtls_mpi_init return.",
            }]),
            "S": make_sarif([]),   # desaparece tras el fix → TP
        },
        "coverity": {
            "V": make_coverity_json([{
                "checker": "NULL_RETURNS",
                "file_path": "dhm.c",
                "line": 148,   # ±2 líneas respecto a CodeQL → misma ventana → TP_overlap
                "cwe": "CWE-476",
                "message": "NULL_RETURNS: mbedtls_mpi_init may return null.",
            }]),
            "S": make_coverity_json([]),
        },
    },

    # -----------------------------------------------------------------------
    # CVE-2020-36421 — integer-overflow en bignum.c
    # Solo CodeQL detecta → TP_unique_CodeQL
    # -----------------------------------------------------------------------
    "CVE-2020-36421": {
        "codeql": {
            "V": make_sarif([{
                "rule_id": "cpp/integer-overflow-tainted",
                "uri": "bignum.c",
                "line": 200,
                "message": "Integer overflow in mpi_exp_mod when e_len==0.",
            }]),
            "S": make_sarif([]),
        },
        "coverity": {
            "V": make_coverity_json([
                # Coverity reporta algo en bignum.c pero en un checker
                # de familia diferente (RESOURCE_LEAK → "other") y en
                # otro archivo → no es candidato para CWE-190
                {
                    "checker": "RESOURCE_LEAK",
                    "file_path": "bignum.c",
                    "line": 350,
                    "cwe": "",
                    "message": "Resource leak in error path.",
                }
            ]),
            "S": make_coverity_json([{
                "checker": "RESOURCE_LEAK",
                "file_path": "bignum.c",
                "line": 350,
                "cwe": "",
                "message": "Resource leak in error path.",
            }]),   # persiste → FP_Coverity (pero de familia "other", no del CVE)
        },
    },

    # -----------------------------------------------------------------------
    # CVE-2022-46392 — OOB read en x509.c
    # Solo Coverity detecta → TP_unique_Coverity
    # -----------------------------------------------------------------------
    "CVE-2022-46392": {
        "codeql": {
            "V": make_sarif([]),   # CodeQL no detecta → FN_CodeQL
            "S": make_sarif([]),
        },
        "coverity": {
            "V": make_coverity_json([
                # Dos findings del mismo defecto (duplicados internos de Coverity)
                {
                    "checker": "OVERRUN",
                    "file_path": "x509.c",
                    "line": 312,
                    "cwe": "CWE-125",
                    "message": "Out-of-bounds read in mbedtls_x509_get_name.",
                },
                {
                    "checker": "BUFFER_SIZE",
                    "file_path": "x509.c",
                    "line": 315,   # ±3 líneas del anterior → misma ventana → deduplicado
                    "cwe": "CWE-125",
                    "message": "Buffer size check missing in x509_get_name.",
                },
            ]),
            "S": make_coverity_json([]),   # desaparece → TP_Coverity (1 deduplicado)
        },
    },

    # -----------------------------------------------------------------------
    # CVE-2022-46393 — heap-overflow en asn1parse.c
    # Ambas detectan en V; CodeQL además tiene un FP que persiste en S
    # -----------------------------------------------------------------------
    "CVE-2022-46393": {
        "codeql": {
            "V": make_sarif([
                # 3 findings: 2 son duplicados (misma ventana de línea)
                {
                    "rule_id": "cpp/overflow-buffer",
                    "uri": "asn1parse.c",
                    "line": 87,
                    "message": "Heap overflow in asn1_get_tag length handling.",
                },
                {
                    "rule_id": "cpp/overflow-buffer",
                    "uri": "asn1parse.c",
                    "line": 91,   # ±4 → misma ventana (bucket 87//20 == 91//20 == 4)
                    "message": "Heap overflow in asn1_get_tag (alternative path).",
                },
                # Este finding persiste en S → FP (ruta diferente de código)
                {
                    "rule_id": "cpp/overrunning-write",
                    "uri": "asn1parse.c",
                    "line": 200,  # línea distinta → bucket diferente
                    "message": "Potential overrunning write in mbedtls_asn1_get_mpi.",
                },
            ]),
            "S": make_sarif([
                # El finding en línea 200 persiste → FP_CodeQL
                {
                    "rule_id": "cpp/overrunning-write",
                    "uri": "asn1parse.c",
                    "line": 200,
                    "message": "Potential overrunning write in mbedtls_asn1_get_mpi.",
                }
            ]),
        },
        "coverity": {
            "V": make_coverity_json([{
                "checker": "HEAP_OVERFLOW",
                "file_path": "asn1parse.c",
                "line": 89,   # dentro de ±10 de la línea 87 → TP_overlap con CodeQL
                "cwe": "CWE-122",
                "message": "Heap-based buffer overflow in asn1_get_tag.",
            }]),
            "S": make_coverity_json([]),  # desaparece → TP_Coverity
        },
    },

    # -----------------------------------------------------------------------
    # CVE-2023-43615 — use-after-free en ssl_tls13_client.c
    # Ambas detectan → TP_overlap
    # -----------------------------------------------------------------------
    "CVE-2023-43615": {
        "codeql": {
            "V": make_sarif([{
                "rule_id": "cpp/use-after-free",
                "uri": "ssl_tls13_client.c",
                "line": 445,
                "message": "Use-after-free: ssl->session_negotiate freed before access.",
            }]),
            "S": make_sarif([]),
        },
        "coverity": {
            "V": make_coverity_json([{
                "checker": "USE_AFTER_FREE",
                "file_path": "ssl_tls13_client.c",
                "line": 447,   # ±2 líneas → misma ventana
                "cwe": "CWE-416",
                "message": "USE_AFTER_FREE: session_negotiate accessed after free.",
            }]),
            "S": make_coverity_json([]),
        },
    },
}

# FN estructurales del GT v2 — todos los 5 se marcan en el mock
STRUCTURAL_FN_CVES = [
    "CVE-2020-16150",
    "CVE-2021-24119",
    "CVE-2019-16910",
    "CVE-2020-10932",
    "CVE-2024-23170",
]


# ---------------------------------------------------------------------------
# Escritura de archivos
# ---------------------------------------------------------------------------

def write_mock_results(output_dir: str, project: str = "mbedtls"):
    base = Path(output_dir)

    for cve_id, data in MOCK_SCENARIOS.items():
        log.info(f"Generando mock para {cve_id}")

        for tool, versions in data.items():
            tool_base = base / "raw" / tool / project / cve_id
            tool_base.mkdir(parents=True, exist_ok=True)

            for version, content in versions.items():
                if tool == "codeql":
                    out_path = tool_base / f"{version}.sarif"
                    with open(out_path, "w") as f:
                        json.dump(content, f, indent=2)
                elif tool == "coverity":
                    out_path = tool_base / f"{version}.json"
                    with open(out_path, "w") as f:
                        json.dump(content, f, indent=2)

                # Meta file
                meta = {
                    "tool": tool,
                    "project": project,
                    "cve": cve_id,
                    "version": version,
                    "commit": "mock-commit",
                    "structural_fn": False,
                }
                meta_path = tool_base / f"{version}.meta.json"
                with open(meta_path, "w") as f:
                    json.dump(meta, f, indent=2)

    # FN estructurales: solo marker
    for cve_id in STRUCTURAL_FN_CVES:
        for tool in ["codeql", "coverity"]:
            marker_dir = base / "raw" / tool / project / cve_id
            marker_dir.mkdir(parents=True, exist_ok=True)
            with open(marker_dir / "structural_fn.json", "w") as f:
                json.dump({"type": "structural_fn", "cve": cve_id,
                           "sast_detectable": False}, f, indent=2)

    log.info(f"\n✓ Mock results escritos en: {output_dir}")
    log.info(f"  Escenarios: {list(MOCK_SCENARIOS.keys())}")
    log.info(f"  FN estructurales: {STRUCTURAL_FN_CVES}")


def print_expected_metrics():
    print("\n" + "="*60)
    print("MÉTRICAS ESPERADAS CON DATOS MOCK (mbedTLS)")
    print("="*60)
    print("""
  N_evaluable = 5

  Instance-level:
    TP_CodeQL   = 4  (todos excepto CVE-2022-46392)
    TP_Coverity = 4  (todos excepto CVE-2020-36421)
    TP_overlap  = 3  (CVE-2021-43666, CVE-2022-46393, CVE-2023-43615)
    TP_unique_CodeQL   = 1  (CVE-2020-36421)
    TP_unique_Coverity = 1  (CVE-2022-46392)
    TP_union    = 5
    FN_CodeQL   = 1  (CVE-2022-46392)
    FN_Coverity = 1  (CVE-2020-36421)

    Recall_CodeQL   = 4/5 = 0.80
    Recall_Coverity = 4/5 = 0.80
    Recall_union    = 5/5 = 1.00
    Marginal_gain   = 1.00 - 0.80 = 0.20

  Finding-level (line_window=10):
    CodeQL V deduplicado CVE-2022-46393:
      líneas 87 y 91 → bucket 87//20=4 y 91//20=4 → SAME BUCKET → 1 finding dedup
      línea 200 → bucket 200//20=10 → finding separado (persiste en S → FP_CodeQL)
    Total FP_CodeQL finding-level = 1  (CVE-2022-46393 línea 200)
    Total FP_Coverity finding-level = 0
""")


def main():
    p = argparse.ArgumentParser(description="Mock runner para tests del pipeline SAST")
    p.add_argument("--output-dir", default="/tmp/mock_results")
    p.add_argument("--project", default="mbedtls")
    p.add_argument("--expected", action="store_true",
                   help="Imprimir métricas esperadas y salir")
    args = p.parse_args()

    if args.expected:
        print_expected_metrics()
        return

    write_mock_results(args.output_dir, args.project)
    print_expected_metrics()


if __name__ == "__main__":
    main()
