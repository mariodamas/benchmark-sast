"""
corpus_b/runner/parallel_runner.py
====================================
Runner paralelo para corpus_b (EMBOSS Shen et al. ISSTA 2025).
Ejecuta CodeQL Y Coverity sobre los mismos commits V/S.

Diseño de fases:
  Fase A: git checkout + build (I/O bound) → MAX 3 workers
  Fase B: codeql analyze (CPU bound)       → MAX 4 workers
  Fase C: cov-analyze (CPU bound)          → MAX 2 workers (Coverity es pesado)

Diferencia con corpus original: aquí el build_script es por proyecto,
no por CVE. Todos los defectos del mismo proyecto comparten build logic.

Uso (desde sast-benchmark/):
  python corpus_b/runner/parallel_runner.py                    # todos los proyectos
  python corpus_b/runner/parallel_runner.py --project raylib   # solo un proyecto
  python corpus_b/runner/parallel_runner.py --skip-coverity    # solo CodeQL
  python corpus_b/runner/parallel_runner.py --phase A          # solo build
"""

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import yaml

# ── Configuración ──────────────────────────────────────────────────────────────
CODEQL_BINARY   = Path("/opt/codeql/codeql")
COVERITY_HOME   = Path("/opt/cov-analysis")
REPOS_BASE      = Path(os.environ.get("REPOS_BASE", "/tmp/repos_b"))
RESULTS_BASE    = Path("corpus_b/results")
BUILD_SCRIPTS   = Path("corpus_b/runner/build_scripts")
CORPUS_B_DIR    = Path("corpus_b/corpus")

MAX_BUILD_WORKERS    = 3
MAX_CODEQL_WORKERS   = 4
MAX_COVERITY_WORKERS = 2

# Mapeo proyecto → repo URL (para clonado automático)
REPO_URLS = {
    "apache_nuttx":       "https://github.com/apache/nuttx.git",
    "contiki_ng_emboss":  "https://github.com/contiki-ng/contiki-ng.git",
    "raylib":             "https://github.com/raysan5/raylib.git",
    "mbed_os":            "https://github.com/ARMmbed/mbed-os.git",
    "epk2extract":        "https://github.com/openlgtv/epk2extract.git",
}
# ───────────────────────────────────────────────────────────────────────────────


def clone_if_needed(project: str) -> Path:
    """Clona el repositorio si no existe ya en REPOS_BASE."""
    repo_path = REPOS_BASE / project
    if repo_path.exists():
        print(f"[REPO] {project}: ya existe en {repo_path}")
        return repo_path

    url = REPO_URLS.get(project)
    if not url:
        raise ValueError(f"No hay URL configurada para proyecto: {project}")

    print(f"[CLONE] {project}: clonando desde {url} ...")
    REPOS_BASE.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth=100", url, str(repo_path)],
        check=True
    )
    print(f"[CLONE] {project}: completado → {repo_path}")
    return repo_path


def validate_affected_file_in_db(db_path: Path, affected_file: str,
                                   instance_id: str) -> bool:
    """
    Verifica que el fichero afectado fue compilado antes de analizar.
    Corta el experimento pronto si el build es incompleto.
    Devuelve True si el fichero está en src.zip, False si no.
    """
    src_zip = db_path / "src.zip"
    if not src_zip.exists():
        print(f"[ERROR] {instance_id}: src.zip no encontrado en {db_path}")
        return False

    with zipfile.ZipFile(src_zip) as z:
        names = z.namelist()

    found = any(affected_file in name for name in names)

    if not found:
        stem = Path(affected_file).stem
        similar = [n for n in names if stem in n][:3]
        print(f"[INVALID_BUILD] {instance_id}: '{affected_file}' ausente en src.zip")
        if similar:
            print(f"  Ficheros similares: {similar}")
        return False

    print(f"[BUILD_OK] {instance_id}: '{affected_file}' confirmado en src.zip")
    return True


def build_both_tools(instance: dict, project: str,
                     repos_base: Path) -> dict:
    """
    Fase A: checkout + build instrumented para CodeQL Y Coverity.
    Un solo checkout sirve para ambas herramientas.
    """
    instance_id  = instance["id"]
    repo_path    = repos_base / project
    build_script = BUILD_SCRIPTS / project / "build.sh"

    if not build_script.exists():
        return {
            "instance_id": instance_id, "project": project,
            "versions": {"V": "error_no_build_script", "S": "error_no_build_script"},
            "error": f"Build script no encontrado: {build_script}"
        }

    result = {"instance_id": instance_id, "project": project, "versions": {}}

    commit_vulnerable = instance.get("commit_vulnerable")
    commit_fix        = instance.get("commit_fix")

    if not commit_vulnerable or not commit_fix:
        print(f"[SKIP_BUILD] {instance_id}: needs_manual_verification=true, sin commits")
        result["versions"]["V"] = "skipped_needs_verification"
        result["versions"]["S"] = "skipped_needs_verification"
        return result

    for version, commit in [("V", commit_vulnerable), ("S", commit_fix)]:
        db_path_codeql   = RESULTS_BASE / "codeql"   / project / instance_id / version / "db"
        db_path_coverity = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"

        if db_path_codeql.exists() and db_path_coverity.exists():
            print(f"[SKIP_BUILD] {instance_id}/{version}: ya existe")
            result["versions"][version] = "skipped"
            continue

        # Checkout al commit objetivo
        subprocess.run(
            ["git", "-C", str(repo_path), "checkout", "-f", commit],
            check=True, capture_output=True
        )
        # Limpiar submódulos si los hay
        subprocess.run(
            ["git", "-C", str(repo_path), "submodule", "update", "--init", "--recursive"],
            capture_output=True
        )

        env = {**os.environ, "REPO_PATH": str(repo_path)}

        # ── Build CodeQL ────────────────────────────────────────────────────
        if not db_path_codeql.exists():
            db_path_codeql.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run([
                    str(CODEQL_BINARY), "database", "create", str(db_path_codeql),
                    "--language=cpp",
                    f"--command=bash {build_script}",
                    "--source-root", str(repo_path),
                    "--threads=2",
                    "--overwrite"
                ], check=True, env=env)
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] {instance_id}/{version}: CodeQL build falló: {e}")
                result["versions"][version] = "error_codeql_build"
                continue

        # ── Validar build ──────────────────────────────────────────────────
        affected_file = instance.get("affected_file", "")
        if affected_file and not validate_affected_file_in_db(
            db_path_codeql, affected_file, f"{instance_id}/{version}"
        ):
            result["versions"][version] = "invalid_build"
            continue

        # ── Build Coverity ─────────────────────────────────────────────────
        if not db_path_coverity.exists():
            db_path_coverity.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run([
                    str(COVERITY_HOME / "bin" / "cov-build"),
                    "--dir", str(db_path_coverity),
                    "bash", str(build_script)
                ], check=True, env=env)
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] {instance_id}/{version}: Coverity build falló: {e}")
                result["versions"][version] = "error_coverity_build"
                continue

        result["versions"][version] = "built"

    return result


def analyze_codeql(instance: dict, project: str) -> dict:
    """Fase B: análisis CodeQL sobre DBs ya construidas."""
    instance_id = instance["id"]
    query       = instance.get("codeql_query", "")

    for version in ["V", "S"]:
        db_path   = RESULTS_BASE / "codeql" / project / instance_id / version / "db"
        sarif_out = RESULTS_BASE / "codeql" / project / instance_id / f"{version}.sarif"

        if sarif_out.exists():
            print(f"[SKIP_CODEQL] {instance_id}/{version}: SARIF ya existe")
            continue

        if not db_path.exists():
            print(f"[SKIP_CODEQL] {instance_id}/{version}: DB no disponible")
            continue

        sarif_out.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(CODEQL_BINARY), "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={sarif_out}",
            "--threads=4",
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        ]
        # Añadir query específica si está definida
        if query:
            cmd.append(query)

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] {instance_id}/{version}: CodeQL analyze falló: {e}")
            return {"instance_id": instance_id, "tool": "codeql", "status": "error"}

    return {"instance_id": instance_id, "tool": "codeql", "status": "done"}


def analyze_coverity(instance: dict, project: str) -> dict:
    """Fase C: análisis Coverity sobre cov_dirs ya construidos."""
    instance_id = instance["id"]

    for version in ["V", "S"]:
        cov_dir  = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"
        json_out = RESULTS_BASE / "coverity" / project / instance_id / f"{version}.json"

        if json_out.exists():
            print(f"[SKIP_COVERITY] {instance_id}/{version}: JSON ya existe")
            continue

        if not cov_dir.exists():
            print(f"[SKIP_COVERITY] {instance_id}/{version}: cov_dir no disponible")
            continue

        try:
            subprocess.run([
                str(COVERITY_HOME / "bin" / "cov-analyze"),
                "--dir", str(cov_dir),
                "--security",
                "--enable", "NULL_RETURNS",
                "--enable", "BUFFER_SIZE",
                "--enable", "INTEGER_OVERFLOW",
                "--enable", "TAINTED_SCALAR",
                "--enable", "OVERRUN",
                "--enable", "USE_AFTER_FREE",
            ], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] {instance_id}/{version}: cov-analyze falló: {e}")
            return {"instance_id": instance_id, "tool": "coverity", "status": "error"}

        json_out.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run([
                str(COVERITY_HOME / "bin" / "cov-format-errors"),
                "--dir", str(cov_dir),
                "--json-output-v8", str(json_out)
            ], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] {instance_id}/{version}: cov-format-errors falló: {e}")
            return {"instance_id": instance_id, "tool": "coverity", "status": "error"}

    return {"instance_id": instance_id, "tool": "coverity", "status": "done"}


def load_instances(project_filter: str | None = None) -> list[dict]:
    """Carga todas las instancias evaluables de corpus_b."""
    all_instances = []
    gt_paths = sorted(CORPUS_B_DIR.glob("*/ground_truth.yaml"))

    if not gt_paths:
        print(f"[ERROR] No se encontraron ground_truth.yaml en {CORPUS_B_DIR}")
        sys.exit(1)

    for gt_path in gt_paths:
        with open(gt_path) as f:
            gt = yaml.safe_load(f)

        project = gt["project"]

        if project_filter and project != project_filter:
            continue

        for inst in gt.get("instances", []):
            if inst.get("structural_fn", False):
                continue  # FN estructurales: excluir del denominador
            if inst.get("needs_manual_verification") and not inst.get("commit_fix"):
                print(f"[SKIP] {inst['id']}: needs_manual_verification=true sin commit_fix")
                continue
            inst["_project"] = project
            all_instances.append(inst)

    return all_instances


def print_summary(build_results: dict, all_instances: list, valid_instances: list):
    """Imprime un resumen del estado del pipeline."""
    print("\n" + "="*60)
    print("RESUMEN FASE A (Builds)")
    print("="*60)
    by_status: dict[str, list] = {}
    for inst_id, res in build_results.items():
        for ver, status in res.get("versions", {}).items():
            by_status.setdefault(status, []).append(f"{inst_id}/{ver}")

    for status, entries in sorted(by_status.items()):
        print(f"  {status:30s}: {len(entries):3d}")

    print(f"\n  Total instancias cargadas : {len(all_instances)}")
    print(f"  Instancias con build OK   : {len(valid_instances)}")
    print(f"  Instancias saltadas/error : {len(all_instances) - len(valid_instances)}")


def run_corpus_b(
    project_filter: str | None = None,
    skip_coverity: bool = False,
    phase: str | None = None,
):
    """Punto de entrada principal."""
    start_time = datetime.now()

    all_instances = load_instances(project_filter)

    print(f"\nCorpus B: {len(all_instances)} instancias evaluables")
    print(f"Proyectos: {sorted(set(i['_project'] for i in all_instances))}")
    if project_filter:
        print(f"Filtro activo: --project {project_filter}")

    # ── Clonar repositorios si no existen ─────────────────────────────────────
    projects_needed = set(i["_project"] for i in all_instances)
    for proj in projects_needed:
        try:
            clone_if_needed(proj)
        except Exception as e:
            print(f"[ERROR] No se pudo clonar {proj}: {e}")

    if phase in (None, "A"):
        # ── FASE A — Builds paralelos ──────────────────────────────────────────
        print("\n=== FASE A: Compilación paralela (CodeQL + Coverity) ===")
        build_results: dict[str, dict] = {}
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=MAX_BUILD_WORKERS) as ex:
            futures = {
                ex.submit(build_both_tools, inst, inst["_project"], REPOS_BASE): inst["id"]
                for inst in all_instances
            }
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    build_results[r["instance_id"]] = r
                    versions_str = ", ".join(
                        f"{v}={s}" for v, s in r["versions"].items()
                    )
                    print(f"  ✓ Build: {r['instance_id']} [{versions_str}]")
                except Exception as e:
                    inst_id = futures[f]
                    print(f"  ✗ Build EXCEPTION {inst_id}: {e}")
                    build_results[inst_id] = {"instance_id": inst_id, "versions": {}}

        valid_instances = [
            inst for inst in all_instances
            if all(
                build_results.get(inst["id"], {}).get("versions", {}).get(v)
                in ("built", "skipped")
                for v in ["V", "S"]
            )
        ]

        print_summary(build_results, all_instances, valid_instances)

        if not valid_instances:
            print("\n[ERROR] Ninguna instancia tiene build válido. Revisar build scripts.")
            return

        # Persistir resultado de fase A
        RESULTS_BASE.mkdir(parents=True, exist_ok=True)
        phase_a_out = RESULTS_BASE / "phase_a_results.json"
        with open(phase_a_out, "w") as f:
            json.dump(build_results, f, indent=2)
        print(f"\n  Resultados fase A guardados en: {phase_a_out}")

        if phase == "A":
            return

    else:
        # Si se salta la fase A, cargar resultados previos
        phase_a_out = RESULTS_BASE / "phase_a_results.json"
        if phase_a_out.exists():
            with open(phase_a_out) as f:
                build_results = json.load(f)
            valid_instances = [
                inst for inst in all_instances
                if all(
                    build_results.get(inst["id"], {}).get("versions", {}).get(v)
                    in ("built", "skipped")
                    for v in ["V", "S"]
                )
            ]
        else:
            print("[WARN] No hay resultados de fase A previos. Ejecutando con todas las instancias.")
            valid_instances = all_instances

    if phase in (None, "B"):
        # ── FASE B — CodeQL paralelo ───────────────────────────────────────────
        print("\n=== FASE B: Análisis CodeQL paralelo ===")
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=MAX_CODEQL_WORKERS) as ex:
            futures = {
                ex.submit(analyze_codeql, inst, inst["_project"]): inst["id"]
                for inst in valid_instances
            }
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    status_icon = "✓" if r["status"] == "done" else "✗"
                    print(f"  {status_icon} CodeQL: {r['instance_id']} [{r['status']}]")
                except Exception as e:
                    inst_id = futures[f]
                    print(f"  ✗ CodeQL EXCEPTION {inst_id}: {e}")

        if phase == "B":
            return

    if phase in (None, "C") and not skip_coverity:
        # ── FASE C — Coverity paralelo ─────────────────────────────────────────
        print("\n=== FASE C: Análisis Coverity paralelo ===")
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=MAX_COVERITY_WORKERS) as ex:
            futures = {
                ex.submit(analyze_coverity, inst, inst["_project"]): inst["id"]
                for inst in valid_instances
            }
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    status_icon = "✓" if r["status"] == "done" else "✗"
                    print(f"  {status_icon} Coverity: {r['instance_id']} [{r['status']}]")
                except Exception as e:
                    inst_id = futures[f]
                    print(f"  ✗ Coverity EXCEPTION {inst_id}: {e}")

    elapsed = datetime.now() - start_time
    print(f"\n=== Corpus B completado en {elapsed} ===")
    print(f"Resultados en: {RESULTS_BASE}")
    print("Siguiente paso: python deduplicator/dedup_findings.py --corpus b")


def main():
    parser = argparse.ArgumentParser(
        description="Runner paralelo para corpus_b (EMBOSS Shen et al. ISSTA 2025)"
    )
    parser.add_argument(
        "--project",
        help="Ejecutar solo para un proyecto (e.g. raylib, apache_nuttx)",
    )
    parser.add_argument(
        "--skip-coverity",
        action="store_true",
        help="Ejecutar solo CodeQL, omitir Coverity",
    )
    parser.add_argument(
        "--phase",
        choices=["A", "B", "C"],
        help="Ejecutar solo una fase (A=build, B=codeql, C=coverity)",
    )
    args = parser.parse_args()

    # Validar herramientas
    if not CODEQL_BINARY.exists():
        print(f"[ERROR] CodeQL no encontrado en {CODEQL_BINARY}")
        print("  Instalar: https://github.com/github/codeql-action/releases")
        sys.exit(1)

    if not args.skip_coverity and not (COVERITY_HOME / "bin" / "cov-build").exists():
        print(f"[WARN] Coverity no encontrado en {COVERITY_HOME}")
        print("  Continuando con --skip-coverity implícito")
        args.skip_coverity = True

    run_corpus_b(
        project_filter=args.project,
        skip_coverity=args.skip_coverity,
        phase=args.phase,
    )


if __name__ == "__main__":
    main()
