#!/usr/bin/env python3
"""
deduplicator/dedup_findings.py
================================
Motor de deduplicación de findings SAST entre CodeQL y Coverity.

PROBLEMA QUE RESUELVE:
  Un único defecto en el código fuente puede generar múltiples alertas
  (e.g., CodeQL reporta la misma vulnerabilidad en 3 rutas de ejecución
  distintas, y Coverity en 2 checkers solapados). Sin deduplicación,
  "ambas juntas" parece mejor porque genera más ruido, no más cobertura.

CLAVE DE DEDUPLICACIÓN:
  (project, cve_id, version, file_path_normalizado, cwe_family, line_window, semantic_class)

  - file_path_normalizado:  ruta relativa a la raíz del repo (sin prefijos absolutos)
  - line_window:            ventana de ±LINE_WINDOW líneas para absorber
                            diferencias de numeración entre herramientas
                            (CodeQL puede reportar en la llamada, Coverity en la definición)
  - cwe_family:             agrupación semántica (buffer-overflow, integer-overflow,
                            null-deref, use-after-free, side-channel, other)
  - semantic_class:         clase derivada del checker name (para casos donde
                            el mismo CWE tiene subtipos que no solapan)

SALIDA:
  results/deduplicated/{project}/{cve_id}/{V|S}_dedup.json
  Cada finding deduplicado tiene una de estas categorías:
    TP_V_DISAPPEARS:  detectado en V, no en S → verdadero positivo
    FP_PERSISTS:      detectado en V y en S   → falso positivo
    NOISE:            no mapea a ninguna instancia del GT
    DUPLICATE:        duplicado de otro finding ya contabilizado

USO:
    python dedup_findings.py \
        --ground-truth ../corpus/mbedtls/ground_truth.yaml \
        --codeql-results ../results/raw/codeql/mbedtls \
        --coverity-results ../results/raw/coverity/mbedtls \
        --output-dir ../results/deduplicated/mbedtls \
        [--line-window 10] \
        [--verbose]
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import NamedTuple

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

LINE_WINDOW_DEFAULT = 10   # ±10 líneas para absorber diferencias

# ---------------------------------------------------------------------------
# Mapeo de checker names → CWE family semántica
# Cubre los checkers de CodeQL (rule IDs) y Coverity (checker names)
# ---------------------------------------------------------------------------
CHECKER_TO_CWE_FAMILY = {
    # CodeQL rule IDs
    "cpp/buffer-not-checked":           "buffer-overflow",
    "cpp/overflow-buffer":              "buffer-overflow",
    "cpp/overrunning-write":            "buffer-overflow",
    "cpp/overrunning-write-with-alloc": "buffer-overflow",
    "cpp/pointer-overflow-check":       "buffer-overflow",
    "cpp/integer-overflow-tainted":     "integer-overflow",
    "cpp/signed-overflow-check":        "integer-overflow",
    "cpp/unsigned-overflow-check":      "integer-overflow",
    "cpp/null-argument-to-called-function": "null-deref",
    "cpp/nullptr-dereference":          "null-deref",
    "cpp/use-after-free":               "use-after-free",
    "cpp/memory-may-not-be-freed":      "use-after-free",
    # Coverity checker names
    "NULL_RETURNS":                     "null-deref",
    "FORWARD_NULL":                     "null-deref",
    "INTEGER_OVERFLOW":                 "integer-overflow",
    "OVERFLOW_BEFORE_WIDEN":            "integer-overflow",
    "NEGATIVE_RETURNS":                 "integer-overflow",
    "BUFFER_SIZE":                      "buffer-overflow",
    "OVERRUN":                          "buffer-overflow",
    "HEAP_OVERFLOW":                    "buffer-overflow",
    "STACK_USE_AFTER_RETURN":           "buffer-overflow",
    "USE_AFTER_FREE":                   "use-after-free",
    "RESOURCE_LEAK":                    "other",
}

CWE_TO_FAMILY = {
    "CWE-476": "null-deref",
    "CWE-190": "integer-overflow",
    "CWE-125": "buffer-overflow",
    "CWE-122": "buffer-overflow",
    "CWE-121": "buffer-overflow",
    "CWE-119": "buffer-overflow",
    "CWE-416": "use-after-free",
    "CWE-208": "side-channel",
    "CWE-203": "side-channel",
}


class NormalizedFinding(NamedTuple):
    """Representación canónica de un finding después de la normalización."""
    tool: str           # "codeql" | "coverity"
    project: str
    cve_id: str
    version: str        # "V" | "S"
    file_path: str      # normalizado (relativo)
    line: int
    cwe_family: str
    checker: str        # rule_id (CodeQL) o checker_name (Coverity)
    message: str
    raw_finding: dict   # finding original sin modificar


# ---------------------------------------------------------------------------
# Parsers de formato de salida de cada herramienta
# ---------------------------------------------------------------------------

def parse_sarif_findings(sarif_path: str, meta: dict) -> list[NormalizedFinding]:
    """
    Parsea un fichero SARIF (CodeQL) y devuelve NormalizedFindings.
    El SARIF de CodeQL usa el esquema OASIS SARIF 2.1.0.
    """
    findings = []
    if not Path(sarif_path).exists():
        log.warning(f"SARIF no encontrado: {sarif_path}")
        return findings

    with open(sarif_path) as f:
        sarif = json.load(f)

    for run in sarif.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "CodeQL")
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})

                file_path = _normalize_path(artifact.get("uri", ""))
                line = region.get("startLine", 0)
                cwe_family = _checker_to_family(rule_id)

                findings.append(NormalizedFinding(
                    tool="codeql",
                    project=meta["project"],
                    cve_id=meta["cve"],
                    version=meta["version"],
                    file_path=file_path,
                    line=line,
                    cwe_family=cwe_family,
                    checker=rule_id,
                    message=message[:200],
                    raw_finding={"rule": rule_id, "file": file_path, "line": line},
                ))
    return findings


def parse_coverity_json_findings(json_path: str, meta: dict) -> list[NormalizedFinding]:
    """
    Parsea el JSON v8 de Coverity.
    Campos relevantes: checker, subcategory, file, function, mainEventLineNumber,
    checkerProperties.cweCategory, impact.
    """
    findings = []
    if not Path(json_path).exists():
        log.warning(f"JSON Coverity no encontrado: {json_path}")
        return findings

    with open(json_path) as f:
        data = json.load(f)

    for issue in data.get("issues", []):
        checker = issue.get("checkerName", "UNKNOWN")
        file_path = _normalize_path(issue.get("mainEventFilePathname", ""))
        line = issue.get("mainEventLineNumber", 0)
        cwe_family = _checker_to_family(checker)
        # Coverity JSON v8 puede incluir el CWE en checkerProperties
        cwe_from_props = (
            issue.get("checkerProperties", {}).get("cweCategory", "") or ""
        )
        if cwe_from_props and cwe_family == "other":
            cwe_family = CWE_TO_FAMILY.get(cwe_from_props, "other")

        findings.append(NormalizedFinding(
            tool="coverity",
            project=meta["project"],
            cve_id=meta["cve"],
            version=meta["version"],
            file_path=file_path,
            line=line,
            cwe_family=cwe_family,
            checker=checker,
            message=issue.get("checkerProperties", {}).get("subcategoryShortDescription", "")[:200],
            raw_finding={
                "checker": checker,
                "file": file_path,
                "line": line,
                "impact": issue.get("impact", ""),
            },
        ))
    return findings


# ---------------------------------------------------------------------------
# Normalización auxiliar
# ---------------------------------------------------------------------------

def _normalize_path(raw_path: str) -> str:
    """
    Elimina prefijos absolutos y normaliza separadores.
    /home/user/repos/mbedtls/library/dhm.c → library/dhm.c
    file:///home/user/repos/mbedtls/library/dhm.c → library/dhm.c
    """
    path = re.sub(r"^file:///", "", raw_path)
    # Eliminar cualquier prefijo hasta el primer componente del proyecto
    # Asume que el repo está en algún lugar del path y el código en subdirectorios
    for repo_marker in ["mbedtls/", "wolfssl/", "lwip/"]:
        if repo_marker in path:
            path = path.split(repo_marker, 1)[-1]
            break
    return path.replace("\\", "/").lstrip("/")


def _checker_to_family(checker_id: str) -> str:
    """Convierte un rule_id/checker_name a la CWE family del benchmark."""
    # Búsqueda exacta
    family = CHECKER_TO_CWE_FAMILY.get(checker_id)
    if family:
        return family
    # Búsqueda parcial (CodeQL rule IDs pueden tener sufijos)
    checker_lower = checker_id.lower()
    if any(k in checker_lower for k in ["buffer", "overrun", "overflow", "bound"]):
        return "buffer-overflow"
    if any(k in checker_lower for k in ["integer", "arith", "wrap"]):
        return "integer-overflow"
    if any(k in checker_lower for k in ["null", "nullptr", "deref"]):
        return "null-deref"
    if any(k in checker_lower for k in ["use-after", "uaf", "dangling", "freed"]):
        return "use-after-free"
    if any(k in checker_lower for k in ["timing", "side-channel", "constant-time"]):
        return "side-channel"
    return "other"


# ---------------------------------------------------------------------------
# Motor de deduplicación
# ---------------------------------------------------------------------------

class DeduplicationKey(NamedTuple):
    """
    Clave canónica para identificar un defecto único.
    Dos findings que comparten esta clave son el mismo defecto.

    CRÍTICO: version NO forma parte de la clave.
    La misma clave se usa tanto en la versión V como en S para
    poder comparar si el defecto desaparece (TP) o persiste (FP).
    """
    project: str
    cve_id: str
    file_path: str
    cwe_family: str
    line_bucket: int    # line // (2 * LINE_WINDOW) → agrupa líneas en ventanas


def compute_dedup_key(f: NormalizedFinding, line_window: int) -> DeduplicationKey:
    bucket = f.line // (2 * line_window) if f.line > 0 else 0
    return DeduplicationKey(
        project=f.project,
        cve_id=f.cve_id,
        file_path=f.file_path,
        cwe_family=f.cwe_family,
        line_bucket=bucket,
    )


def deduplicate(
    findings_v_codeql: list[NormalizedFinding],
    findings_s_codeql: list[NormalizedFinding],
    findings_v_coverity: list[NormalizedFinding],
    findings_s_coverity: list[NormalizedFinding],
    gt_instance: dict,
    line_window: int,
) -> dict:
    """
    Clasifica cada finding deduplicado en una de las 4 categorías.
    Devuelve el registro completo para el evaluador.

    Algoritmo:
    1. Pre-filtrar findings relevantes para esta instancia del GT:
       - Mismo archivo afectado (o sufijo/basename compatible)
       - CWE family compatible (o "other" como comodín)
       Sin este filtro, ruido de otras partes del código contamina
       el cómputo de TP/FP para el CVE evaluado.
    2. Deduplicar findings propios de cada herramienta (intra-tool).
    3. Comparar conjunto deduplicado V vs S por clave sin versión:
       - Clave en V pero NO en S  → TP_V_DISAPPEARS
       - Clave en V Y en S        → FP_PERSISTS
    4. Métricas de overlap entre herramientas.
    """
    affected_file = _normalize_path(gt_instance.get("affected_file", ""))
    cwe_family_gt = gt_instance.get("cwe_family", "other")

    # -----------------------------------------------------------------------
    # Pre-filtro: solo findings relevantes para esta instancia del GT
    # -----------------------------------------------------------------------
    def _is_relevant(f: NormalizedFinding) -> bool:
        # Match de archivo: igual, sufijo, o mismo basename
        fp = f.file_path.lower()
        gp = affected_file.lower()
        file_ok = (
            fp == gp
            or fp.endswith(gp)
            or gp.endswith(fp)
            or (Path(fp).name == Path(gp).name and Path(fp).name != "")
        )
        # Match de CWE family: "other" es comodín; resto requiere coincidencia
        family_ok = (
            f.cwe_family == "other"
            or cwe_family_gt == "other"
            or f.cwe_family == cwe_family_gt
        )
        return file_ok and family_ok

    def _filter(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        return [f for f in findings if _is_relevant(f)]

    rel_cq_v = _filter(findings_v_codeql)
    rel_cq_s = _filter(findings_s_codeql)
    rel_cv_v = _filter(findings_v_coverity)
    rel_cv_s = _filter(findings_s_coverity)

    def dedup_list(findings: list[NormalizedFinding]) -> dict[DeduplicationKey, NormalizedFinding]:
        """Devuelve el primer finding de cada clave (deduplicación intra-herramienta)."""
        seen = {}
        for f in findings:
            key = compute_dedup_key(f, line_window)
            if key not in seen:
                seen[key] = f
        return seen

    # Deduplicar por herramienta y versión (sobre findings ya filtrados)
    dedup_cq_v = dedup_list(rel_cq_v)
    dedup_cq_s = dedup_list(rel_cq_s)
    dedup_cv_v = dedup_list(rel_cv_v)
    dedup_cv_s = dedup_list(rel_cv_s)

    # -----------------------------------------------------------------------
    # Clasificar findings de CodeQL en V
    # -----------------------------------------------------------------------
    cq_classified = {}
    for key, finding in dedup_cq_v.items():
        # Un finding desaparece en S si NO hay ningún finding en S con la misma clave
        if key in dedup_cq_s:
            category = "FP_PERSISTS"
        else:
            category = "TP_V_DISAPPEARS"
        cq_classified[key] = {"finding": finding._asdict(), "category": category}

    # -----------------------------------------------------------------------
    # Clasificar findings de Coverity en V
    # -----------------------------------------------------------------------
    cv_classified = {}
    for key, finding in dedup_cv_v.items():
        if key in dedup_cv_s:
            category = "FP_PERSISTS"
        else:
            category = "TP_V_DISAPPEARS"
        cv_classified[key] = {"finding": finding._asdict(), "category": category}

    # -----------------------------------------------------------------------
    # Métricas de overlap entre herramientas (solo TPs)
    # -----------------------------------------------------------------------
    tp_keys_cq = {k for k, v in cq_classified.items() if v["category"] == "TP_V_DISAPPEARS"}
    tp_keys_cv = {k for k, v in cv_classified.items() if v["category"] == "TP_V_DISAPPEARS"}

    tp_overlap_keys    = tp_keys_cq & tp_keys_cv
    tp_unique_cq_keys  = tp_keys_cq - tp_keys_cv
    tp_unique_cv_keys  = tp_keys_cv - tp_keys_cq
    tp_union_keys      = tp_keys_cq | tp_keys_cv

    fp_keys_cq = {k for k, v in cq_classified.items() if v["category"] == "FP_PERSISTS"}
    fp_keys_cv = {k for k, v in cv_classified.items() if v["category"] == "FP_PERSISTS"}

    result = {
        "cve_id": gt_instance["cve"],
        "cwe": gt_instance["cwe"],
        "cwe_family": cwe_family_gt,
        "affected_file": affected_file,
        "line_window": line_window,

        # --- Conteos de findings deduplicados en V (tras filtro) ---
        "findings_dedup_V_codeql":   len(dedup_cq_v),
        "findings_dedup_V_coverity": len(dedup_cv_v),

        # --- Clasificación por herramienta ---
        "TP_V_DISAPPEARS_codeql":   len(tp_keys_cq),
        "FP_PERSISTS_codeql":       len(fp_keys_cq),
        "TP_V_DISAPPEARS_coverity": len(tp_keys_cv),
        "FP_PERSISTS_coverity":     len(fp_keys_cv),

        # --- Overlap y unicidad (métricas clave del benchmark) ---
        "TP_overlap":          len(tp_overlap_keys),
        "TP_unique_codeql":    len(tp_unique_cq_keys),
        "TP_unique_coverity":  len(tp_unique_cv_keys),
        "TP_union":            len(tp_union_keys),
        "FP_union":            len(fp_keys_cq | fp_keys_cv),

        # --- Detalle de findings clasificados ---
        "classified_codeql":  [
            {"key": str(k), **v} for k, v in cq_classified.items()
        ],
        "classified_coverity": [
            {"key": str(k), **v} for k, v in cv_classified.items()
        ],
    }
    return result


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------

def load_meta(meta_path: str) -> dict:
    if not Path(meta_path).exists():
        return {}
    with open(meta_path) as f:
        return json.load(f)


def load_findings_for_instance(
    results_dir: str, cve_id: str, version: str,
    tool: str, gt_instance: dict, project: str
) -> list[NormalizedFinding]:
    inst_dir = Path(results_dir) / cve_id
    meta_path = str(inst_dir / f"{version}.meta.json")
    meta = load_meta(meta_path)
    if not meta:
        meta = {"tool": tool, "project": project, "cve": cve_id, "version": version}

    if tool == "codeql":
        sarif_path = str(inst_dir / f"{version}.sarif")
        return parse_sarif_findings(sarif_path, meta)
    elif tool == "coverity":
        json_path = str(inst_dir / f"{version}.json")
        return parse_coverity_json_findings(json_path, meta)
    return []


def is_structural_fn(results_dir: str, cve_id: str) -> bool:
    marker = Path(results_dir) / cve_id / "structural_fn.json"
    return marker.exists()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ground-truth", required=True)
    p.add_argument("--codeql-results", required=True)
    p.add_argument("--coverity-results", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--line-window", type=int, default=LINE_WINDOW_DEFAULT)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    with open(args.ground_truth) as f:
        gt = yaml.safe_load(f)

    project = gt["project"]
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    all_results = []

    for instance in gt["instances"]:
        cve_id = instance["cve"]
        log.info(f"\nDeduplicando: {cve_id}")

        # FN estructurales: marcados pero no evaluados
        if instance.get("structural_fn"):
            entry = {
                "cve_id": cve_id,
                "cwe": instance["cwe"],
                "structural_fn": True,
                "sast_detectable": False,
                "note": instance.get("notes", ""),
            }
            all_results.append(entry)
            out_path = Path(args.output_dir) / f"{cve_id}_dedup.json"
            with open(out_path, "w") as f:
                json.dump(entry, f, indent=2)
            log.info(f"  → FN estructural documentado.")
            continue

        # Cargar findings de ambas herramientas para V y S
        cq_v  = load_findings_for_instance(args.codeql_results,  cve_id, "V", "codeql",  instance, project)
        cq_s  = load_findings_for_instance(args.codeql_results,  cve_id, "S", "codeql",  instance, project)
        cv_v  = load_findings_for_instance(args.coverity_results, cve_id, "V", "coverity", instance, project)
        cv_s  = load_findings_for_instance(args.coverity_results, cve_id, "S", "coverity", instance, project)

        log.info(f"  CodeQL   V={len(cq_v)} findings | S={len(cq_s)} findings")
        log.info(f"  Coverity V={len(cv_v)} findings | S={len(cv_s)} findings")

        result = deduplicate(cq_v, cq_s, cv_v, cv_s, instance, args.line_window)
        result["structural_fn"] = False
        result["project"] = project
        all_results.append(result)

        out_path = Path(args.output_dir) / f"{cve_id}_dedup.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)

        log.info(f"  TP_codeql={result['TP_V_DISAPPEARS_codeql']} "
                 f"TP_coverity={result['TP_V_DISAPPEARS_coverity']} "
                 f"TP_overlap={result['TP_overlap']} "
                 f"TP_union={result['TP_union']}")

    # Resumen consolidado
    summary_path = Path(args.output_dir) / "summary_dedup.json"
    with open(summary_path, "w") as f:
        json.dump({"project": project, "instances": all_results}, f, indent=2)

    log.info(f"\n✓ Deduplicación completada. Resumen: {summary_path}")


if __name__ == "__main__":
    main()
