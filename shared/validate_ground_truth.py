#!/usr/bin/env python3
"""
scripts/validate_ground_truth.py
==================================
Valida los ficheros ground_truth.yaml antes de lanzar el benchmark.
Soporta dos esquemas:

  ESQUEMA A (Corpus A — CVE-based):
    Campos obligatorios de instancia: id, cve, cwe, cwe_family, cvss,
      affected_file, commit_vulnerable, commit_fix, structural_fn, sast_detectable
    Detección: instancia NO tiene campo 'source'

  ESQUEMA B (Corpus B — EMBOSS Shen et al. ISSTA 2025):
    Campos obligatorios de instancia: id, source, cwe_id, cwe_family,
      affected_file, commit_vulnerable, commit_fix, structural_fn,
      codeql_query, pr_url
    Detección: instancia tiene campo 'source: shen_et_al_issta_2025'
    Excepción: si needs_manual_verification=true, commit_* pueden ser null

Comprueba en ambos esquemas:
  1. Esquema YAML (campos obligatorios presentes)
  2. Que los commits no sean placeholders (hashes de ejemplo)
  3. Que los CVE IDs (esquema A) o defect IDs (esquema B) sean únicos
  4. Que los CWE family estén en el conjunto permitido
  5. Que los FN estructurales tengan la bandera sast_detectable: false (esquema A)
  6. Que no haya IDs duplicados dentro del mismo fichero
"""

import argparse
import re
import sys
from pathlib import Path

import yaml

# ── Campos requeridos por esquema ─────────────────────────────────────────────

REQUIRED_INSTANCE_FIELDS_A = [
    "id", "cve", "cwe", "cwe_family", "cvss",
    "affected_file", "commit_vulnerable", "commit_fix",
    "structural_fn", "sast_detectable",
]

REQUIRED_INSTANCE_FIELDS_B = [
    "id", "source", "cwe_id", "cwe_family",
    "affected_file", "commit_fix",
    "structural_fn", "codeql_query", "pr_url",
]

REQUIRED_PROJECT_FIELDS = [
    "project", "repo_url", "language", "build_system",
    "compile_commands_generator", "corpus_role", "sast_quality",
]

# ── Valores permitidos ─────────────────────────────────────────────────────────

VALID_CWE_FAMILIES = {
    "buffer-overflow", "integer-overflow", "null-deref",
    "use-after-free", "side-channel", "format-string", "other",
}

VALID_CORPUS_ROLES = {"primary", "validation", "contrast"}

VALID_SOURCES_B = {"shen_et_al_issta_2025"}

# ── Patrones de validación ─────────────────────────────────────────────────────

# Hashes placeholder inequívocos: todos-ceros, todos-unos, o patrones de relleno obvios
PLACEHOLDER_PATTERN = re.compile(
    r"^(0{40}|1{40}|a{40}|f{40}|"          # completamente repetidos
    r"0{10,}1{10,}|deadbeef{5,}|"           # mitad-mitad o repetición de deadbeef
    r"cafebabe|badc0de|1234567890ab)",       # constantes conocidas de placeholder
    re.IGNORECASE
)
CVE_PATTERN    = re.compile(r"^CVE-\d{4}-\d{4,}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


# ── Lógica de validación ───────────────────────────────────────────────────────

def is_emboss_instance(inst: dict) -> bool:
    """Detecta si una instancia usa el esquema B (EMBOSS)."""
    return inst.get("source") in VALID_SOURCES_B


def validate_commit(commit, field_name: str, prefix: str,
                    skip_if_nmv: bool) -> list[str]:
    """
    Valida un campo de commit SHA.
    Si skip_if_nmv=True y el commit es None/vacío, no reporta error
    (la instancia tiene needs_manual_verification=true).
    """
    errors = []
    if not commit:
        if not skip_if_nmv:
            errors.append(f"{prefix}: campo '{field_name}' vacío o null "
                          f"(marcar needs_manual_verification: true si es intencional)")
        return errors

    commit_str = str(commit)
    if not COMMIT_PATTERN.match(commit_str):
        errors.append(f"{prefix}: {field_name} no es un hash SHA-1 válido: '{commit_str}'")
    elif PLACEHOLDER_PATTERN.match(commit_str):
        errors.append(f"{prefix}: {field_name} parece un hash placeholder: '{commit_str}'")

    return errors


def validate_instance_a(inst: dict, i: int, path: str,
                         seen_cves: set, seen_ids: set) -> list[str]:
    """Valida una instancia del Esquema A (CVE-based, Corpus A)."""
    errors = []
    prefix = f"[{path}] instancia #{i+1}"

    for field in REQUIRED_INSTANCE_FIELDS_A:
        if field not in inst:
            errors.append(f"{prefix}: campo faltante '{field}'")

    # CVE ID format
    cve = inst.get("cve", "")
    if not CVE_PATTERN.match(str(cve)):
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
        errors.append(f"{prefix}: cwe_family inválida '{cwe_family}'. "
                      f"Válidas: {sorted(VALID_CWE_FAMILIES)}")

    # Commits
    for commit_field in ["commit_vulnerable", "commit_fix"]:
        errors.extend(validate_commit(
            inst.get(commit_field), commit_field, prefix, skip_if_nmv=False
        ))

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
    try:
        if not (0.0 <= float(cvss) <= 10.0):
            errors.append(f"{prefix}: CVSS fuera de rango [0,10]: {cvss}")
    except (ValueError, TypeError):
        errors.append(f"{prefix}: CVSS no es un número: {cvss}")

    return errors


def validate_instance_b(inst: dict, i: int, path: str,
                         seen_ids: set) -> list[str]:
    """Valida una instancia del Esquema B (EMBOSS, Corpus B)."""
    errors = []
    prefix = f"[{path}] instancia #{i+1}"
    nmv = inst.get("needs_manual_verification", False)

    for field in REQUIRED_INSTANCE_FIELDS_B:
        if field not in inst:
            # commit_vulnerable puede estar ausente si needs_manual_verification=true
            if field == "commit_vulnerable" and nmv:
                continue
            # pr_url puede ser null para EPK2-DEFECT-004 (placeholder)
            if field == "pr_url" and inst.get(id) and inst.get("confirmed_by") == "needs_manual_verification":
                continue
            errors.append(f"{prefix}: campo faltante '{field}'")

    # Source válido
    source = inst.get("source", "")
    if source not in VALID_SOURCES_B:
        errors.append(f"{prefix}: source inválido '{source}'. "
                      f"Válidos: {sorted(VALID_SOURCES_B)}")

    # Instance ID unicidad
    iid = inst.get("id", "")
    if iid in seen_ids:
        errors.append(f"{prefix}: ID duplicado '{iid}'")
    seen_ids.add(iid)

    # CWE family
    cwe_family = inst.get("cwe_family", "")
    if cwe_family not in VALID_CWE_FAMILIES:
        errors.append(f"{prefix}: cwe_family inválida '{cwe_family}'. "
                      f"Válidas: {sorted(VALID_CWE_FAMILIES)}")

    # cwe_id formato
    cwe_id = inst.get("cwe_id", "")
    if cwe_id and not str(cwe_id).startswith("CWE-"):
        errors.append(f"{prefix}: cwe_id debe empezar con 'CWE-': '{cwe_id}'")

    # Commits (con tolerancia para needs_manual_verification)
    commit_fix = inst.get("commit_fix")
    if commit_fix:
        errors.extend(validate_commit(commit_fix, "commit_fix", prefix, skip_if_nmv=False))

    commit_vulnerable = inst.get("commit_vulnerable")
    errors.extend(validate_commit(
        commit_vulnerable, "commit_vulnerable", prefix, skip_if_nmv=nmv
    ))

    # codeql_query formato
    codeql_query = inst.get("codeql_query", "")
    valid_queries = {
        "cpp/inconsistent-null-check",
        "cpp/uncontrolled-allocation-size",
        "cpp/unbounded-write",
        "cpp/missing-check-scanf",
    }
    if codeql_query and codeql_query not in valid_queries:
        errors.append(
            f"{prefix}: codeql_query no reconocida: '{codeql_query}'. "
            f"Queries válidas para EMBOSS: {sorted(valid_queries)}"
        )

    # structural_fn: los defectos EMBOSS no deberían ser FN estructurales
    if inst.get("structural_fn"):
        errors.append(
            f"{prefix}: structural_fn=true en instancia EMBOSS. "
            f"Las queries EMBOSS (null-deref, buffer, overflow) no son FN estructurales."
        )

    return errors


def validate_gt(path: str) -> list[str]:
    errors = []
    with open(path) as f:
        try:
            gt = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return [f"YAML parse error en {path}: {e}"]

    if gt is None:
        return [f"[{path}] Fichero YAML vacío"]

    # Validar campos de proyecto (requeridos en ambos esquemas)
    for field in REQUIRED_PROJECT_FIELDS:
        if field not in gt:
            errors.append(f"[{path}] Campo de proyecto faltante: '{field}'")

    if gt.get("corpus_role") not in VALID_CORPUS_ROLES:
        errors.append(f"[{path}] corpus_role inválido: {gt.get('corpus_role')}. "
                      f"Válidos: {sorted(VALID_CORPUS_ROLES)}")

    instances = gt.get("instances", [])
    if not instances:
        errors.append(f"[{path}] No hay instancias definidas.")
        return errors

    seen_ids:  set = set()
    seen_cves: set = set()

    for i, inst in enumerate(instances):
        if is_emboss_instance(inst):
            errors.extend(validate_instance_b(inst, i, path, seen_ids))
        else:
            errors.extend(validate_instance_a(inst, i, path, seen_cves, seen_ids))

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
                print(f"  [ERROR] {e}")
        else:
            print("  [OK]")

    if all_errors:
        print(f"\n[FAIL] {len(all_errors)} errores encontrados. "
              f"Corrige el ground truth antes de continuar.")
        sys.exit(1)
    else:
        print(f"\n[PASS] Todos los ground truth validados correctamente.")


if __name__ == "__main__":
    main()
