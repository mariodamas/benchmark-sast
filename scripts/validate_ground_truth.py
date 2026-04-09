#!/usr/bin/env python3
"""
scripts/validate_ground_truth.py
==================================
Valida los ficheros ground_truth.yaml antes de lanzar el benchmark.
Comprueba:
  1. Esquema YAML (campos obligatorios presentes)
  2. Que los commits no sean placeholders (hashes de ejemplo)
  3. Que los CVE IDs existan en el formato correcto
  4. Que los CWE family estén en el conjunto permitido
  5. Que los FN estructurales tengan la bandera sast_detectable: false
  6. Que no haya CVE IDs duplicados dentro del mismo proyecto
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

REQUIRED_INSTANCE_FIELDS = [
    "id", "cve", "cwe", "cwe_family", "cvss",
    "affected_file", "commit_vulnerable", "commit_fix",
    "structural_fn", "sast_detectable",
]

REQUIRED_PROJECT_FIELDS = [
    "project", "repo_url", "language", "build_system",
    "compile_commands_generator", "corpus_role", "sast_quality",
]

VALID_CWE_FAMILIES = {
    "buffer-overflow", "integer-overflow", "null-deref",
    "use-after-free", "side-channel", "other",
}

VALID_CORPUS_ROLES = {"primary", "validation"}

# Hashes placeholder inequívocos: todos-ceros, todos-unos, o patrones de relleno obvios
# NO marcamos como placeholder hashes reales que casualmente empiezan con chars repetidos
PLACEHOLDER_PATTERN = re.compile(
    r"^(0{40}|1{40}|a{40}|f{40}|"          # completamente repetidos
    r"0{10,}1{10,}|deadbeef{5,}|"           # mitad-mitad o repetición de deadbeef
    r"cafebabe|badc0de|1234567890ab)",       # constantes conocidas de placeholder
    re.IGNORECASE
)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def validate_gt(path: str) -> list[str]:
    errors = []
    with open(path) as f:
        try:
            gt = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [f"YAML parse error en {path}: {e}"]

    # Validar campos de proyecto
    for field in REQUIRED_PROJECT_FIELDS:
        if field not in gt:
            errors.append(f"[{path}] Campo de proyecto faltante: '{field}'")

    if gt.get("corpus_role") not in VALID_CORPUS_ROLES:
        errors.append(f"[{path}] corpus_role inválido: {gt.get('corpus_role')}")

    instances = gt.get("instances", [])
    if not instances:
        errors.append(f"[{path}] No hay instancias definidas.")
        return errors

    seen_cves = set()
    seen_ids = set()

    for i, inst in enumerate(instances):
        prefix = f"[{path}] instancia #{i+1}"

        # Campos obligatorios
        for field in REQUIRED_INSTANCE_FIELDS:
            if field not in inst:
                errors.append(f"{prefix}: campo faltante '{field}'")

        # CVE ID format
        cve = inst.get("cve", "")
        if not CVE_PATTERN.match(cve):
            errors.append(f"{prefix}: CVE ID inválido '{cve}'")
        if cve in seen_cves:
            errors.append(f"{prefix}: CVE duplicado '{cve}'")
        seen_cves.add(cve)

        # Instance ID unicidad
        iid = inst.get("id", "")
        if iid in seen_ids:
            errors.append(f"{prefix}: ID duplicado '{iid}'")
        seen_ids.add(iid)

        # CWE family
        cwe_family = inst.get("cwe_family", "")
        if cwe_family not in VALID_CWE_FAMILIES:
            errors.append(f"{prefix}: cwe_family inválida '{cwe_family}'. Válidas: {VALID_CWE_FAMILIES}")

        # Commits: formato hex-40 (solo si están definidos)
        for commit_field in ["commit_vulnerable", "commit_fix"]:
            commit = inst.get(commit_field, "")
            if commit and not COMMIT_PATTERN.match(commit):
                errors.append(f"{prefix}: {commit_field} no es un hash SHA-1 válido: '{commit}'")
            if commit and PLACEHOLDER_PATTERN.match(commit):
                errors.append(f"{prefix}: {commit_field} parece un hash placeholder: '{commit}'")

        # Coherencia structural_fn / sast_detectable
        if inst.get("structural_fn") and inst.get("sast_detectable"):
            errors.append(
                f"{prefix}: inconsistencia — structural_fn=true pero sast_detectable=true. "
                f"Los FN estructurales no son detectables por SAST."
            )
        if not inst.get("structural_fn") and inst.get("sast_detectable") is False:
            errors.append(
                f"{prefix}: sast_detectable=false en instancia no structural_fn. "
                f"¿Es un FN estructural no marcado correctamente?"
            )

        # CVSS range
        cvss = inst.get("cvss", 0)
        if not (0.0 <= float(cvss) <= 10.0):
            errors.append(f"{prefix}: CVSS fuera de rango [0,10]: {cvss}")

    return errors


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--gt", nargs="+", required=True, help="Rutas a los ground_truth.yaml")
    args = p.parse_args()

    all_errors = []
    for gt_path in args.gt:
        print(f"Validando: {gt_path}")
        errors = validate_gt(gt_path)
        all_errors.extend(errors)
        if errors:
            for e in errors:
                print(f"  ✗ {e}")
        else:
            print(f"  ✓ OK")

    if all_errors:
        print(f"\n✗ {len(all_errors)} errores encontrados. Corrige el ground truth antes de continuar.")
        sys.exit(1)
    else:
        print(f"\n✓ Todos los ground truth validados correctamente.")


if __name__ == "__main__":
    main()
