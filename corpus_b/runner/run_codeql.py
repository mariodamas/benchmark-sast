"""
corpus_b/runner/run_codeql.py
==============================
Runner CodeQL individual para corpus_b (EMBOSS).
Analiza una instancia específica o todas las de un proyecto.

Uso (desde sast-benchmark/):
  # Analizar una instancia concreta
  python corpus_b/runner/run_codeql.py --id NUTTX-DEFECT-001

  # Analizar todas las instancias de un proyecto
  python corpus_b/runner/run_codeql.py --project apache_nuttx

  # Analizar solo la versión vulnerable
  python corpus_b/runner/run_codeql.py --id RAYLIB-DEFECT-001 --version V

Para ejecución en bloque usar corpus_b/runner/parallel_runner.py.
"""

import argparse
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

CODEQL_BINARY = Path(os.environ.get("CODEQL_BINARY", "/opt/codeql/codeql"))
REPOS_BASE    = Path(os.environ.get("REPOS_BASE",    "/tmp/repos_b"))
RESULTS_BASE  = Path("corpus_b/results")
BUILD_SCRIPTS = Path("corpus_b/runner/build_scripts")
CORPUS_B_DIR  = Path("corpus_b/corpus")

# Suite estándar + extended para asegurar cobertura de las 4 queries EMBOSS
CODEQL_SUITE  = "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls"


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


def build_codeql_db(instance: dict, project: str, version: str) -> Path | None:
    """Construye la base de datos CodeQL para una versión V o S."""
    instance_id = instance["id"]
    commit = instance.get("commit_vulnerable" if version == "V" else "commit_fix")

    if not commit:
        print(f"[SKIP] {instance_id}/{version}: commit no disponible")
        return None

    repo_path    = REPOS_BASE / project
    build_script = BUILD_SCRIPTS / project / "build.sh"
    db_path      = RESULTS_BASE / "codeql" / project / instance_id / version / "db"

    if db_path.exists():
        print(f"[SKIP_BUILD] {instance_id}/{version}: DB ya existe en {db_path}")
        return db_path

    if not repo_path.exists():
        print(f"[ERROR] Repo no clonado: {repo_path}")
        print(f"  Ejecutar: git clone <url> {repo_path}")
        return None

    if not build_script.exists():
        print(f"[ERROR] Build script no encontrado: {build_script}")
        return None

    print(f"[BUILD] {instance_id}/{version}: checkout {commit[:12]}...")
    subprocess.run(
        ["git", "-C", str(repo_path), "checkout", "-f", commit],
        check=True, capture_output=True
    )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "REPO_PATH": str(repo_path)}

    print(f"[BUILD] {instance_id}/{version}: codeql database create...")
    try:
        subprocess.run([
            str(CODEQL_BINARY), "database", "create", str(db_path),
            "--language=cpp",
            f"--command=bash {build_script}",
            "--source-root", str(repo_path),
            "--threads=2",
            "--overwrite"
        ], check=True, env=env)
    except subprocess.CalledProcessError:
        print(f"[ERROR] {instance_id}/{version}: fallo en codeql database create")
        return None

    # Validar que el fichero afectado está en la DB
    affected_file = instance.get("affected_file", "")
    if affected_file:
        src_zip = db_path / "src.zip"
        if src_zip.exists():
            with zipfile.ZipFile(src_zip) as z:
                names = z.namelist()
            if not any(affected_file in n for n in names):
                print(f"[WARN] {instance_id}/{version}: '{affected_file}' no encontrado en src.zip")
                print(f"  La herramienta puede generar FN por build incompleto")

    return db_path


def analyze_instance(instance: dict, project: str, version: str) -> dict:
    """Ejecuta CodeQL analyze sobre una instancia/versión."""
    instance_id = instance["id"]
    query       = instance.get("codeql_query", "")

    db_path   = RESULTS_BASE / "codeql" / project / instance_id / version / "db"
    sarif_out = RESULTS_BASE / "codeql" / project / instance_id / f"{version}.sarif"

    if sarif_out.exists():
        print(f"[SKIP_ANALYZE] {instance_id}/{version}: SARIF ya existe")
        return {"status": "skipped", "sarif": str(sarif_out)}

    if not db_path.exists():
        # Intentar construir la DB primero
        db_path_result = build_codeql_db(instance, project, version)
        if not db_path_result:
            return {"status": "error_no_db"}

    sarif_out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(CODEQL_BINARY), "database", "analyze", str(db_path),
        "--format=sarif-latest",
        f"--output={sarif_out}",
        "--threads=4",
        CODEQL_SUITE,
    ]
    if query:
        cmd.append(query)

    print(f"[ANALYZE] {instance_id}/{version}: codeql database analyze...")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        print(f"[ERROR] {instance_id}/{version}: fallo en codeql analyze")
        return {"status": "error_analyze"}

    # Parsear SARIF para contar alertas relevantes
    try:
        with open(sarif_out) as f:
            sarif = json.load(f)
        total_results = sum(
            len(run.get("results", []))
            for run in sarif.get("runs", [])
        )
        print(f"[RESULT] {instance_id}/{version}: {total_results} alertas en SARIF")
    except Exception:
        total_results = -1

    return {"status": "done", "sarif": str(sarif_out), "alert_count": total_results}


def classify_instance(instance: dict, project: str) -> dict:
    """
    Clasifica una instancia como TP/FP/FN comparando V vs S.
    Basado en la metodología del benchmark:
      TP: alerta presente en V y ausente en S
      FP: alerta presente en V y también en S
      FN: alerta ausente en V (no detectada)
    """
    instance_id   = instance["id"]
    affected_file = instance.get("affected_file", "")
    codeql_query  = instance.get("codeql_query", "")

    result_v = {"instance_id": instance_id, "version": "V"}
    result_s = {"instance_id": instance_id, "version": "S"}

    for version, res_dict in [("V", result_v), ("S", result_s)]:
        sarif_path = RESULTS_BASE / "codeql" / project / instance_id / f"{version}.sarif"
        if not sarif_path.exists():
            res_dict["found"] = None
            res_dict["alert_count"] = 0
            continue

        with open(sarif_path) as f:
            sarif = json.load(f)

        # Buscar alertas en el fichero afectado con la query correcta
        alerts_in_file = []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                for loc in result.get("locations", []):
                    uri = loc.get("physicalLocation", {}) \
                              .get("artifactLocation", {}) \
                              .get("uri", "")
                    if affected_file in uri:
                        alerts_in_file.append({
                            "ruleId": rule_id,
                            "uri": uri,
                            "line": loc.get("physicalLocation", {})
                                       .get("region", {})
                                       .get("startLine", 0)
                        })

        res_dict["found"] = len(alerts_in_file) > 0
        res_dict["alert_count"] = len(alerts_in_file)
        res_dict["alerts"] = alerts_in_file

    # Clasificación
    found_v = result_v.get("found")
    found_s = result_s.get("found")

    if found_v is None:
        classification = "UNKNOWN_NO_SARIF_V"
    elif found_s is None:
        classification = "UNKNOWN_NO_SARIF_S"
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
        "codeql_query":   codeql_query,
        "affected_file":  affected_file,
        "V":              result_v,
        "S":              result_s,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Runner CodeQL individual para corpus_b (EMBOSS)"
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
        help="Solo construir la DB, no analizar"
    )
    parser.add_argument(
        "--classify",
        action="store_true",
        help="Mostrar clasificación TP/FP/FN después del análisis"
    )
    args = parser.parse_args()

    if not CODEQL_BINARY.exists():
        print(f"[ERROR] CodeQL no encontrado en {CODEQL_BINARY}")
        sys.exit(1)

    # Cargar instancias
    if args.id:
        instance, project = find_instance(args.id)
        instances = [(instance, project)]
    else:
        instances_list = load_project_instances(args.project)
        instances = [(inst, args.project) for inst in instances_list]

    print(f"Procesando {len(instances)} instancia(s)...")

    # Procesar
    classifications = []
    for instance, project in instances:
        versions = (
            ["V", "S"] if args.version == "both"
            else [args.version]
        )

        if args.build_only:
            for ver in versions:
                build_codeql_db(instance, project, ver)
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
                          f"alerts={v_data.get('alert_count', 0)}")

    if classifications:
        print("\n" + "="*50)
        print("RESUMEN CLASIFICACIONES")
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
        print(f"\n  Recall CodeQL (corpus_b): {recall:.2%} ({tp}/{tp+fn})")

    # Guardar resultados en JSON
    if classifications:
        out_path = RESULTS_BASE / "codeql_classifications.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(classifications, f, indent=2)
        print(f"\nClasificaciones guardadas en: {out_path}")


if __name__ == "__main__":
    main()
