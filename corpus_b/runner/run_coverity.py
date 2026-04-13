"""
corpus_b/runner/run_coverity.py
================================
Runner Coverity individual para corpus_b (EMBOSS).
Analiza una instancia específica o todas las de un proyecto.

Uso (desde sast-benchmark/):
  # Analizar una instancia concreta
  python corpus_b/runner/run_coverity.py --id NUTTX-DEFECT-001

  # Analizar todas las instancias de un proyecto
  python corpus_b/runner/run_coverity.py --project apache_nuttx

  # Solo construir (cov-build), sin analizar
  python corpus_b/runner/run_coverity.py --id RAYLIB-DEFECT-001 --build-only

Para ejecución en bloque usar corpus_b/runner/parallel_runner.py.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

COVERITY_HOME = Path(os.environ.get("COVERITY_HOME", "/opt/cov-analysis"))
REPOS_BASE    = Path(os.environ.get("REPOS_BASE",    "/tmp/repos_b"))
RESULTS_BASE  = Path("corpus_b/results")
BUILD_SCRIPTS = Path("corpus_b/runner/build_scripts")
CORPUS_B_DIR  = Path("corpus_b/corpus")

COV_BUILD   = COVERITY_HOME / "bin" / "cov-build"
COV_ANALYZE = COVERITY_HOME / "bin" / "cov-analyze"
COV_ERRORS  = COVERITY_HOME / "bin" / "cov-format-errors"

# Checkers Coverity relevantes para las familias CWE del benchmark
COVERITY_CHECKERS = [
    "--enable", "NULL_RETURNS",        # CWE-476 null-deref
    "--enable", "FORWARD_NULL",        # CWE-476 null-deref (variante)
    "--enable", "BUFFER_SIZE",         # CWE-120 buffer-overflow
    "--enable", "OVERRUN",             # CWE-120 buffer-overflow (variante)
    "--enable", "INTEGER_OVERFLOW",    # CWE-190 integer-overflow
    "--enable", "TAINTED_SCALAR",      # CWE-190/120 combinado
    "--enable", "USE_AFTER_FREE",      # CWE-416 (no primario pero útil)
    "--enable", "STRING_OVERFLOW",     # CWE-134 format-string adjacent
]


def find_instance(instance_id: str) -> tuple[dict, str]:
    """Busca una instancia por ID en todos los ground truth de corpus_b."""
    for gt_path in CORPUS_B_DIR.glob("*/ground_truth.yaml"):
        with open(gt_path) as f:
            gt = yaml.safe_load(f)
        for inst in gt.get("instances", []):
            if inst["id"] == instance_id:
                return inst, gt["project"]
    raise ValueError(f"Instancia '{instance_id}' no encontrada en corpus_b/corpus/")


def load_project_instances(project: str) -> list[dict]:
    """Carga todas las instancias evaluables de un proyecto."""
    gt_path = CORPUS_B_DIR / project / "ground_truth.yaml"
    if not gt_path.exists():
        raise FileNotFoundError(f"Ground truth no encontrado: {gt_path}")
    with open(gt_path) as f:
        gt = yaml.safe_load(f)
    return [
        inst for inst in gt.get("instances", [])
        if not inst.get("structural_fn", False)
        and not inst.get("needs_manual_verification", False)
    ]


def build_coverity(instance: dict, project: str, version: str) -> Path | None:
    """Ejecuta cov-build para una instancia/versión."""
    instance_id = instance["id"]
    commit = instance.get("commit_vulnerable" if version == "V" else "commit_fix")

    if not commit:
        print(f"[SKIP] {instance_id}/{version}: commit no disponible")
        return None

    repo_path    = REPOS_BASE / project
    build_script = BUILD_SCRIPTS / project / "build.sh"
    cov_dir      = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"

    if cov_dir.exists():
        print(f"[SKIP_BUILD] {instance_id}/{version}: cov_dir ya existe")
        return cov_dir

    if not repo_path.exists():
        print(f"[ERROR] Repo no clonado: {repo_path}")
        return None

    if not build_script.exists():
        print(f"[ERROR] Build script no encontrado: {build_script}")
        return None

    print(f"[BUILD] {instance_id}/{version}: checkout {commit[:12]}...")
    subprocess.run(
        ["git", "-C", str(repo_path), "checkout", "-f", commit],
        check=True, capture_output=True
    )

    cov_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "REPO_PATH": str(repo_path)}

    print(f"[BUILD] {instance_id}/{version}: cov-build...")
    try:
        subprocess.run([
            str(COV_BUILD),
            "--dir", str(cov_dir),
            "bash", str(build_script)
        ], check=True, env=env)
    except subprocess.CalledProcessError:
        print(f"[ERROR] {instance_id}/{version}: fallo en cov-build")
        return None

    return cov_dir


def analyze_instance(instance: dict, project: str, version: str) -> dict:
    """Ejecuta cov-analyze + cov-format-errors sobre una instancia/versión."""
    instance_id = instance["id"]

    cov_dir  = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"
    json_out = RESULTS_BASE / "coverity" / project / instance_id / f"{version}.json"

    if json_out.exists():
        print(f"[SKIP_ANALYZE] {instance_id}/{version}: JSON ya existe")
        return {"status": "skipped", "json": str(json_out)}

    if not cov_dir.exists():
        cov_dir_result = build_coverity(instance, project, version)
        if not cov_dir_result:
            return {"status": "error_no_cov_dir"}

    print(f"[ANALYZE] {instance_id}/{version}: cov-analyze...")
    try:
        subprocess.run([
            str(COV_ANALYZE),
            "--dir", str(cov_dir),
            "--security",
            *COVERITY_CHECKERS,
        ], check=True)
    except subprocess.CalledProcessError:
        print(f"[ERROR] {instance_id}/{version}: fallo en cov-analyze")
        return {"status": "error_analyze"}

    json_out.parent.mkdir(parents=True, exist_ok=True)
    print(f"[EXPORT] {instance_id}/{version}: cov-format-errors → JSON...")
    try:
        subprocess.run([
            str(COV_ERRORS),
            "--dir", str(cov_dir),
            "--json-output-v8", str(json_out)
        ], check=True)
    except subprocess.CalledProcessError:
        print(f"[ERROR] {instance_id}/{version}: fallo en cov-format-errors")
        return {"status": "error_export"}

    # Contar issues en el JSON exportado
    try:
        with open(json_out) as f:
            data = json.load(f)
        issue_count = len(data.get("issues", []))
        print(f"[RESULT] {instance_id}/{version}: {issue_count} issues en Coverity JSON")
    except Exception:
        issue_count = -1

    return {"status": "done", "json": str(json_out), "issue_count": issue_count}


def classify_instance(instance: dict, project: str) -> dict:
    """
    Clasifica una instancia como TP/FP/FN comparando V vs S.
    Metodología equivalente a run_codeql_emboss.py pero para Coverity JSON.
    """
    instance_id   = instance["id"]
    affected_file = instance.get("affected_file", "")
    cwe_id        = instance.get("cwe_id", "")
    cwe_family    = instance.get("cwe_family", "")

    # Mapeo CWE family → checkers Coverity esperados
    CWE_TO_CHECKER = {
        "null-deref":       ["NULL_RETURNS", "FORWARD_NULL"],
        "buffer-overflow":  ["BUFFER_SIZE", "OVERRUN", "STRING_OVERFLOW"],
        "integer-overflow": ["INTEGER_OVERFLOW", "TAINTED_SCALAR"],
        "format-string":    ["STRING_OVERFLOW", "TAINTED_SCALAR"],
    }
    expected_checkers = set(CWE_TO_CHECKER.get(cwe_family, []))

    result_v = {"instance_id": instance_id, "version": "V"}
    result_s = {"instance_id": instance_id, "version": "S"}

    for version, res_dict in [("V", result_v), ("S", result_s)]:
        json_path = RESULTS_BASE / "coverity" / project / instance_id / f"{version}.json"
        if not json_path.exists():
            res_dict["found"] = None
            res_dict["issue_count"] = 0
            continue

        with open(json_path) as f:
            data = json.load(f)

        issues_in_file = [
            issue for issue in data.get("issues", [])
            if (
                affected_file in issue.get("strippedMainEventFilePathname", "")
                or affected_file in issue.get("mainEventFilePathname", "")
            )
            and (
                not expected_checkers
                or issue.get("checkerName", "") in expected_checkers
            )
        ]

        res_dict["found"] = len(issues_in_file) > 0
        res_dict["issue_count"] = len(issues_in_file)
        res_dict["issues"] = [
            {
                "checker": i.get("checkerName"),
                "file": i.get("strippedMainEventFilePathname"),
                "line": i.get("mainEventLineNumber"),
                "subcategory": i.get("checkerSubcategoryLongDescription", "")[:80],
            }
            for i in issues_in_file
        ]

    found_v = result_v.get("found")
    found_s = result_s.get("found")

    if found_v is None:
        classification = "UNKNOWN_NO_JSON_V"
    elif found_s is None:
        classification = "UNKNOWN_NO_JSON_S"
    elif found_v and not found_s:
        classification = "TP"
    elif found_v and found_s:
        classification = "FP"
    elif not found_v:
        classification = "FN"
    else:
        classification = "UNKNOWN"

    return {
        "id":             instance_id,
        "project":        project,
        "classification": classification,
        "cwe_id":         cwe_id,
        "cwe_family":     cwe_family,
        "affected_file":  affected_file,
        "V":              result_v,
        "S":              result_s,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Runner Coverity individual para corpus_b (EMBOSS)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id",      help="ID de la instancia (e.g. NUTTX-DEFECT-001)")
    group.add_argument("--project", help="Analizar todas las instancias de un proyecto")

    parser.add_argument(
        "--version",
        choices=["V", "S", "both"],
        default="both",
        help="Versión a analizar (default: both)"
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Solo ejecutar cov-build, no analizar"
    )
    parser.add_argument(
        "--classify",
        action="store_true",
        help="Mostrar clasificación TP/FP/FN después del análisis"
    )
    args = parser.parse_args()

    if not COV_BUILD.exists():
        print(f"[ERROR] Coverity no encontrado en {COVERITY_HOME}")
        print("  Verificar instalación: ls -la /opt/cov-analysis/bin/")
        sys.exit(1)

    if args.id:
        instance, project = find_instance(args.id)
        instances = [(instance, project)]
    else:
        instances_list = load_project_instances(args.project)
        instances = [(inst, args.project) for inst in instances_list]

    print(f"Procesando {len(instances)} instancia(s) con Coverity...")

    classifications = []
    for instance, project in instances:
        versions = ["V", "S"] if args.version == "both" else [args.version]

        if args.build_only:
            for ver in versions:
                build_coverity(instance, project, ver)
        else:
            for ver in versions:
                analyze_instance(instance, project, ver)
            if args.classify:
                clf = classify_instance(instance, project)
                classifications.append(clf)
                print(f"\n[CLASSIFICATION] {clf['id']}: {clf['classification']}")
                for ver in ["V", "S"]:
                    v_data = clf.get(ver, {})
                    print(f"  {ver}: found={v_data.get('found')}, "
                          f"issues={v_data.get('issue_count', 0)}")

    if classifications:
        print("\n" + "="*50)
        print("RESUMEN CLASIFICACIONES COVERITY")
        print("="*50)
        counts = {}
        for clf in classifications:
            c = clf["classification"]
            counts[c] = counts.get(c, 0) + 1
        for c, n in sorted(counts.items()):
            print(f"  {c:30s}: {n}")
        total = len(classifications)
        tp = counts.get("TP", 0)
        fn = counts.get("FN", 0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        print(f"\n  Recall Coverity (corpus_b): {recall:.2%} ({tp}/{tp+fn})")

        out_path = RESULTS_BASE / "coverity_classifications.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(classifications, f, indent=2)
        print(f"\nClasificaciones guardadas en: {out_path}")


if __name__ == "__main__":
    main()
