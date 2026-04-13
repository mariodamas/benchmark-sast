#!/usr/bin/env python3
"""
evaluator/instance_evaluator.py
=================================
PROPÓSITO:
  Mapea los findings crudos (SARIF de CodeQL, JSON de Coverity) a las
  instancias del ground truth ANTES de la deduplicación.

  El deduplicador trabaja con findings ya normalizados y clasificados en
  relación al GT. Este módulo es el puente: responde, para cada CVE, si
  el archivo afectado tiene algún finding relevante en la versión V.

DIFERENCIA CON dedup_findings.py:
  - El evaluador opera a nivel de instancia: ¿toca el archivo afectado?
  - El deduplicador opera a nivel de finding: ¿son la misma alerta?
  Se usan en secuencia: evaluador → deduplicador → métricas.

CRITERIOS DE RELEVANCIA DE UN FINDING PARA UNA INSTANCIA:
  Un finding es candidato a TP de la instancia si:
    1. Está en la versión V (antes del fix)
    2. Su file_path_normalizado coincide (exacto o sufijo) con el
       affected_file del GT, O está en el mismo directorio
    3. Su cwe_family coincide con la cwe_family del GT
       (tolerancia: "other" nunca excluye)
    4. Su line está dentro de una ventana respecto al rango del parche
       (cuando está disponible en el GT — campo opcional patch_lines)

  Un finding relevante que desaparece en S → TP confirmado.
  Un finding relevante que persiste en S → FP.
  Ningún finding relevante en V → FN de instancia.

USO:
  Normalmente llamado como módulo por dedup_findings.py.
  También usable standalone:

    python instance_evaluator.py \
        --ground-truth ../corpus/mbedtls/ground_truth.yaml \
        --codeql-sarif  ../results/raw/codeql/mbedtls/CVE-2022-46393/V.sarif \
        --coverity-json ../results/raw/coverity/mbedtls/CVE-2022-46393/V.json \
        --cve CVE-2022-46393 \
        --version V
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tolerancia de matching de rutas
# ---------------------------------------------------------------------------

def paths_match(finding_path: str, gt_path: str) -> bool:
    """
    Dos rutas coinciden si:
      - Son iguales (exacto)
      - finding_path termina en gt_path (sufijo)
      - gt_path es el basename de finding_path
      - Están en el mismo directorio (para casos donde herramientas
        reportan en el .h correspondiente al .c del GT)
    """
    fp = finding_path.replace("\\", "/").lower()
    gp = gt_path.replace("\\", "/").lower()

    if fp == gp:
        return True
    if fp.endswith(gp) or gp.endswith(fp):
        return True
    # Mismo basename (e.g., dhm.c == dhm.c aunque la ruta difiera)
    if Path(fp).name == Path(gp).name:
        return True
    # Mismo directorio inmediato (e.g., library/ para cualquier archivo de mbedTLS)
    if Path(fp).parent.name == Path(gp).parent.name and Path(fp).parent.name:
        return True
    return False


def cwe_families_compatible(finding_family: str, gt_family: str) -> bool:
    """
    "other" es compatible con cualquier familia (no excluye por defecto).
    El resto requiere coincidencia exacta.
    """
    if finding_family == "other" or gt_family == "other":
        return True
    return finding_family == gt_family


# ---------------------------------------------------------------------------
# Parser de SARIF (CodeQL)
# ---------------------------------------------------------------------------

def _normalize_path_sarif(uri: str) -> str:
    path = re.sub(r"^file:///", "", uri)
    for marker in ["mbedtls/", "wolfssl/", "lwip/"]:
        if marker in path:
            return path.split(marker, 1)[-1].replace("\\", "/").lstrip("/")
    return path.replace("\\", "/").lstrip("/")


def _checker_family_from_rule(rule_id: str) -> str:
    """Derivar la cwe_family de un CodeQL rule_id."""
    r = rule_id.lower()
    if any(k in r for k in ["buffer", "overrun", "overflow", "bound", "oob"]):
        return "buffer-overflow"
    if any(k in r for k in ["integer", "arith", "wrap", "signed"]):
        return "integer-overflow"
    if any(k in r for k in ["null", "nullptr", "deref"]):
        return "null-deref"
    if any(k in r for k in ["use-after", "uaf", "dangling", "freed", "free"]):
        return "use-after-free"
    if any(k in r for k in ["timing", "side-channel", "constant"]):
        return "side-channel"
    return "other"


def parse_sarif(sarif_path: str) -> list[dict]:
    """
    Devuelve lista de dicts con: rule_id, file_path, line, cwe_family, message.
    """
    results = []
    if not Path(sarif_path).exists():
        return results
    with open(sarif_path) as f:
        sarif = json.load(f)
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                results.append({
                    "tool": "codeql",
                    "rule_id": rule_id,
                    "file_path": _normalize_path_sarif(uri),
                    "line": line,
                    "cwe_family": _checker_family_from_rule(rule_id),
                    "message": message[:300],
                })
    return results


# ---------------------------------------------------------------------------
# Parser de JSON v8 (Coverity)
# ---------------------------------------------------------------------------

_COV_CHECKER_FAMILY = {
    "NULL_RETURNS": "null-deref",
    "FORWARD_NULL": "null-deref",
    "INTEGER_OVERFLOW": "integer-overflow",
    "OVERFLOW_BEFORE_WIDEN": "integer-overflow",
    "NEGATIVE_RETURNS": "integer-overflow",
    "BUFFER_SIZE": "buffer-overflow",
    "OVERRUN": "buffer-overflow",
    "HEAP_OVERFLOW": "buffer-overflow",
    "STACK_USE_AFTER_RETURN": "buffer-overflow",
    "USE_AFTER_FREE": "use-after-free",
    "RESOURCE_LEAK": "other",
}

_CWE_TO_FAMILY = {
    "CWE-476": "null-deref", "CWE-190": "integer-overflow",
    "CWE-125": "buffer-overflow", "CWE-122": "buffer-overflow",
    "CWE-121": "buffer-overflow", "CWE-119": "buffer-overflow",
    "CWE-416": "use-after-free", "CWE-208": "side-channel",
    "CWE-203": "side-channel",
}


def _normalize_path_cov(raw: str) -> str:
    for marker in ["mbedtls/", "wolfssl/", "lwip/"]:
        if marker in raw:
            return raw.split(marker, 1)[-1].replace("\\", "/").lstrip("/")
    return raw.replace("\\", "/").lstrip("/")


def parse_coverity_json(json_path: str) -> list[dict]:
    results = []
    if not Path(json_path).exists():
        return results
    with open(json_path) as f:
        data = json.load(f)
    for issue in data.get("issues", []):
        checker = issue.get("checkerName", "UNKNOWN")
        file_path = _normalize_path_cov(issue.get("mainEventFilePathname", ""))
        line = issue.get("mainEventLineNumber", 0)
        family = _COV_CHECKER_FAMILY.get(checker, "other")
        # Intentar mejorar family desde CWE en checkerProperties
        cwe_str = issue.get("checkerProperties", {}).get("cweCategory", "")
        if cwe_str and family == "other":
            family = _CWE_TO_FAMILY.get(cwe_str, "other")
        results.append({
            "tool": "coverity",
            "rule_id": checker,
            "file_path": file_path,
            "line": line,
            "cwe_family": family,
            "message": issue.get("checkerProperties", {})
                           .get("subcategoryShortDescription", "")[:300],
        })
    return results


# ---------------------------------------------------------------------------
# Evaluación de instancia
# ---------------------------------------------------------------------------

class InstanceEvaluationResult:
    """Resultado de evaluar una herramienta contra una instancia del GT."""

    def __init__(self, cve_id: str, tool: str, version: str):
        self.cve_id = cve_id
        self.tool = tool
        self.version = version
        self.candidate_findings: list[dict] = []   # Findings que tocan el archivo afectado
        self.non_candidate_findings: list[dict] = []  # Ruido ajeno al archivo

    @property
    def has_candidates(self) -> bool:
        return len(self.candidate_findings) > 0

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "tool": self.tool,
            "version": self.version,
            "candidate_count": len(self.candidate_findings),
            "non_candidate_count": len(self.non_candidate_findings),
            "has_candidates": self.has_candidates,
            "candidates": self.candidate_findings,
        }


def evaluate_instance(
    findings: list[dict],
    instance: dict,
    version: str,
    tool: str,
    file_match_strict: bool = False,
) -> InstanceEvaluationResult:
    """
    Filtra los findings que son candidatos a TP para esta instancia.

    Si file_match_strict=True, requiere coincidencia exacta de ruta.
    Por defecto (False), usa paths_match() con tolerancia de sufijo/basename.

    NOTA: No clasifica en TP/FP todavía — eso lo hace el deduplicador
    comparando V con S. Esta función solo identifica candidatos relevantes.
    """
    cve_id = instance["cve"]
    gt_file = instance.get("affected_file", "")
    gt_family = instance.get("cwe_family", "other")
    patch_lines: Optional[tuple[int, int]] = instance.get("patch_lines")  # (start, end) opcional

    result = InstanceEvaluationResult(cve_id, tool, version)

    for f in findings:
        file_ok = (
            f["file_path"] == gt_file
            if file_match_strict
            else paths_match(f["file_path"], gt_file)
        )
        family_ok = cwe_families_compatible(f["cwe_family"], gt_family)

        # Filtro de línea opcional (si el GT especifica patch_lines)
        line_ok = True
        if patch_lines and f["line"] > 0:
            start, end = patch_lines
            window = 50  # ventana amplia para el filtro de instancia (el dedup usa ±10)
            line_ok = (start - window) <= f["line"] <= (end + window)

        if file_ok and family_ok and line_ok:
            result.candidate_findings.append(f)
        else:
            result.non_candidate_findings.append(f)

    return result


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Evaluador de instancia SAST")
    p.add_argument("--ground-truth", required=True)
    p.add_argument("--cve", required=True, help="CVE ID a evaluar")
    p.add_argument("--version", choices=["V", "S"], required=True)
    p.add_argument("--codeql-sarif", default=None)
    p.add_argument("--coverity-json", default=None)
    p.add_argument("--output", default=None, help="Guardar resultado en JSON")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    with open(args.ground_truth) as f:
        gt = yaml.safe_load(f)

    instance = next((i for i in gt["instances"] if i["cve"] == args.cve), None)
    if not instance:
        log.error(f"CVE {args.cve} no encontrado en {args.ground_truth}")
        sys.exit(1)

    if instance.get("structural_fn"):
        print(f"{args.cve} es un FN estructural — no evaluable con SAST.")
        return

    output = {"cve": args.cve, "version": args.version, "results": {}}

    if args.codeql_sarif:
        findings = parse_sarif(args.codeql_sarif)
        ev = evaluate_instance(findings, instance, args.version, "codeql")
        output["results"]["codeql"] = ev.to_dict()
        print(f"\n[CodeQL] {args.cve} v{args.version}:")
        print(f"  Findings totales:   {len(findings)}")
        print(f"  Candidatos (GT):    {ev.candidate_count if hasattr(ev, 'candidate_count') else len(ev.candidate_findings)}")
        print(f"  Has candidates:     {ev.has_candidates}")

    if args.coverity_json:
        findings = parse_coverity_json(args.coverity_json)
        ev = evaluate_instance(findings, instance, args.version, "coverity")
        output["results"]["coverity"] = ev.to_dict()
        print(f"\n[Coverity] {args.cve} v{args.version}:")
        print(f"  Findings totales:   {len(findings)}")
        print(f"  Candidatos (GT):    {len(ev.candidate_findings)}")
        print(f"  Has candidates:     {ev.has_candidates}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResultado guardado en: {args.output}")


if __name__ == "__main__":
    main()
