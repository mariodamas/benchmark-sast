# runner/parallel_runner.py

import subprocess
import concurrent.futures
import yaml
import os
from pathlib import Path

# ── Configuración ──────────────────────────────────────────────
MAX_BUILD_WORKERS  = 3   # Limitado por I/O de disco y RAM
MAX_ANALYSIS_WORKERS = 6 # Limitado por núcleos CPU disponibles
# ───────────────────────────────────────────────────────────────

def build_codeql_db(cve_entry, repo_path, output_dir):
    """Fase A: compilación instrumentada → base de datos CodeQL"""
    cve_id  = cve_entry["cve_id"]
    project = cve_entry["project"]

    for version, commit in [("V", cve_entry["commit_vulnerable"]),
                             ("S", cve_entry["commit_fix"])]:
        db_path = output_dir / project / cve_id / version / "codeql-db"
        if db_path.exists():
            print(f"[SKIP] DB ya existe: {cve_id}/{version}")
            continue

        # Checkout
        subprocess.run(["git", "-C", repo_path,
                        "checkout", commit], check=True)

        # Build
        subprocess.run([
            "codeql", "database", "create", str(db_path),
            "--language=cpp",
            "--command=./build.sh",
            "--source-root", str(repo_path),
            "--threads=2"   # Pocos threads por build, muchos builds en paralelo
        ], check=True)

    return cve_id, "build_ok"


def analyze_codeql_db(cve_entry, db_base_dir, output_dir):
    """Fase B: análisis de DB ya construida → SARIF"""
    cve_id  = cve_entry["cve_id"]
    project = cve_entry["project"]

    for version in ["V", "S"]:
        db_path   = db_base_dir / project / cve_id / version / "codeql-db"
        sarif_out = output_dir  / project / cve_id / f"{version}.sarif"

        if sarif_out.exists():
            print(f"[SKIP] SARIF ya existe: {cve_id}/{version}")
            continue

        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "codeql", "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={sarif_out}",
            "--threads=4",  # Más threads por análisis, menos jobs paralelos
            "cpp-security-and-quality.qls"
        ], check=True)

    return cve_id, "analysis_ok"


def run_parallel_benchmark(ground_truth_paths, db_dir, results_dir):

    # Cargar todos los CVEs de todos los proyectos
    all_cves = []
    for gt_path in ground_truth_paths:
        with open(gt_path) as f:
            gt = yaml.safe_load(f)
        project = gt["project"]
        for cve in gt["instances"]:
            if not cve.get("structural_fn", False):
                cve["project"] = project
                all_cves.append(cve)

    print(f"Total CVEs evaluables: {len(all_cves)}")

    # ── FASE A: builds en paralelo ─────────────────────────────
    print("\n=== FASE A: Compilación paralela ===")
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_BUILD_WORKERS) as executor:

        futures = {
            executor.submit(
                build_codeql_db, cve,
                Path(f"/tmp/repos/{cve['project']}"),
                Path(db_dir)
            ): cve["cve_id"]
            for cve in all_cves
        }
        for future in concurrent.futures.as_completed(futures):
            cve_id, status = future.result()
            print(f"  ✓ Build completado: {cve_id}")

    # ── FASE B: análisis en paralelo ───────────────────────────
    print("\n=== FASE B: Análisis paralelo ===")
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=MAX_ANALYSIS_WORKERS) as executor:

        futures = {
            executor.submit(
                analyze_codeql_db, cve,
                Path(db_dir),
                Path(results_dir)
            ): cve["cve_id"]
            for cve in all_cves
        }
        for future in concurrent.futures.as_completed(futures):
            cve_id, status = future.result()
            print(f"  ✓ Análisis completado: {cve_id}")
