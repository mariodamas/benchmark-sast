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

Configuración via .env.benchmark (en la raíz del repo):
  CODEQL_BINARY=/usr/local/bin/codeql
  REPOS_BASE=/tmp/repos_b
  RESULTS_BASE=/tmp/benchmark_results
  BENCHMARK_ROOT=/mnt/c/Users/mario/Desktop/INFORMATICA/4º Curso/TFG/sast-benchmark
"""

import argparse
import concurrent.futures
import json
import logging
import os
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import yaml


# ── Carga de .env.benchmark ────────────────────────────────────────────────────

def _load_env_file(path: str = ".env.benchmark") -> dict:
    """Carga variables desde .env.benchmark sin dependencias externas."""
    env_vars: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    env_vars[key.strip()] = val.strip().strip("\"'")
    except FileNotFoundError:
        pass  # .env.benchmark es opcional; se usan los defaults
    return env_vars


_env = _load_env_file()


def _env_get(key: str, default: str) -> str:
    """Lee clave de .env.benchmark, luego de os.environ, luego default."""
    return _env.get(key, os.environ.get(key, default))


# ── Configuración ──────────────────────────────────────────────────────────────

CODEQL_BINARY = Path(_env_get("CODEQL_BINARY", "/opt/codeql/codeql"))
COVERITY_HOME = Path(_env_get("COVERITY_HOME", "/opt/cov-analysis"))
REPOS_BASE    = Path(_env_get("REPOS_BASE",    "/tmp/repos_b"))
RESULTS_BASE  = Path(_env_get("RESULTS_BASE",  "corpus_b/results"))

# BENCHMARK_ROOT: raíz del repo desde WSL2 (e.g. /mnt/c/Users/.../sast-benchmark)
# Si no está en .env.benchmark, se usa "." (CWD cuando se lanza el script).
_BENCHMARK_ROOT = Path(_env_get("BENCHMARK_ROOT", "."))
BUILD_SCRIPTS   = _BENCHMARK_ROOT / "corpus_b" / "runner" / "build_scripts"
CORPUS_B_DIR    = _BENCHMARK_ROOT / "corpus_b" / "corpus"

MAX_BUILD_WORKERS    = int(_env_get("MAX_BUILD_WORKERS",    "3"))
MAX_CODEQL_WORKERS   = int(_env_get("MAX_CODEQL_WORKERS",   "4"))
MAX_COVERITY_WORKERS = int(_env_get("MAX_COVERITY_WORKERS", "2"))

# Mapeo proyecto → repo URL (para clonado automático)
REPO_URLS = {
    "apache_nuttx":       "https://github.com/apache/nuttx.git",
    "contiki_ng_emboss":  "https://github.com/contiki-ng/contiki-ng.git",
    "raylib":             "https://github.com/raysan5/raylib.git",
    "mbed_os":            "https://github.com/ARMmbed/mbed-os.git",
    "epk2extract":        "https://github.com/openlgtv/epk2extract.git",
}

# ── Logging ────────────────────────────────────────────────────────────────────

def _setup_logging() -> logging.Logger:
    log_dir = RESULTS_BASE / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = log_dir / f"run_{timestamp}.log"

    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    log = logging.getLogger("corpus_b")
    log.info(f"Log: {log_file}")
    log.info(f"CODEQL_BINARY : {CODEQL_BINARY}")
    log.info(f"REPOS_BASE    : {REPOS_BASE}")
    log.info(f"RESULTS_BASE  : {RESULTS_BASE}")
    log.info(f"BUILD_SCRIPTS : {BUILD_SCRIPTS}")
    log.info(f"CORPUS_B_DIR  : {CORPUS_B_DIR}")
    return log

# Logger global; se inicializa en main() después de que RESULTS_BASE esté listo
log: logging.Logger = logging.getLogger("corpus_b")


# ── Utilidades ─────────────────────────────────────────────────────────────────

def clone_if_needed(project: str) -> Path:
    """Clona el repositorio si no existe ya en REPOS_BASE."""
    repo_path = REPOS_BASE / project
    if repo_path.exists():
        log.info(f"[REPO] {project}: ya existe en {repo_path}")
        return repo_path

    url = REPO_URLS.get(project)
    if not url:
        raise ValueError(f"No hay URL configurada para proyecto: {project}")

    log.info(f"[CLONE] {project}: clonando desde {url} ...")
    REPOS_BASE.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--progress", url, str(repo_path)],
        check=True,
    )
    log.info(f"[CLONE] {project}: completado → {repo_path}")
    return repo_path


def validate_affected_file_in_db(db_path: Path, affected_file: str,
                                   instance_id: str) -> bool:
    """
    Verifica que el fichero afectado fue compilado antes de analizar.
    Devuelve True si está en src.zip, False si no (INVALID_BUILD, no FN).
    """
    src_zip = db_path / "src.zip"
    if not src_zip.exists():
        log.error(f"[NO_SRC_ZIP] {instance_id}: src.zip no encontrado en {db_path}")
        return False

    with zipfile.ZipFile(src_zip) as z:
        names = z.namelist()

    found = any(affected_file in name for name in names)

    if not found:
        stem = Path(affected_file).stem
        similar = [n for n in names if stem in n][:3]
        c_files = len([n for n in names if n.endswith((".c", ".cpp", ".h"))])
        log.warning(f"[INVALID_BUILD] {instance_id}: '{affected_file}' ausente en src.zip")
        log.warning(f"  Total C/C++ en DB: {c_files} | Similares: {similar}")
        return False

    log.info(f"[BUILD_OK] {instance_id}: '{affected_file}' confirmado en src.zip")
    return True


# ── Fase A: Build ──────────────────────────────────────────────────────────────

def build_both_tools(instance: dict, project: str,
                     skip_coverity: bool = False) -> dict:
    """
    Fase A: checkout + build instrumented para CodeQL (y opcionalmente Coverity).
    Un solo checkout sirve para ambas herramientas.
    """
    instance_id  = instance["id"]
    repo_path    = REPOS_BASE / project
    build_script = BUILD_SCRIPTS / project / "build.sh"

    if not build_script.exists():
        msg = f"Build script no encontrado: {build_script}"
        log.error(f"[ERROR] {instance_id}: {msg}")
        return {
            "instance_id": instance_id, "project": project,
            "versions": {"V": "error_no_build_script", "S": "error_no_build_script"},
            "error": msg,
        }

    result: dict = {"instance_id": instance_id, "project": project, "versions": {}}

    commit_vulnerable = instance.get("commit_vulnerable")
    commit_fix        = instance.get("commit_fix")

    if not commit_vulnerable or not commit_fix:
        log.warning(f"[SKIP_BUILD] {instance_id}: needs_manual_verification=true, sin commits")
        result["versions"]["V"] = "skipped_needs_verification"
        result["versions"]["S"] = "skipped_needs_verification"
        return result

    log_dir = RESULTS_BASE / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    for version, commit in [("V", commit_vulnerable), ("S", commit_fix)]:
        db_path_codeql   = RESULTS_BASE / "codeql"   / project / instance_id / version / "db"
        db_path_coverity = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"

        # Comprobar si ya existe (resume)
        codeql_exists   = db_path_codeql.exists()
        coverity_exists = db_path_coverity.exists() or skip_coverity
        if codeql_exists and coverity_exists:
            log.info(f"[SKIP_BUILD] {instance_id}/{version}: ya existe")
            result["versions"][version] = "skipped"
            continue

        # Checkout al commit objetivo
        log.info(f"[BUILD] {instance_id}/{version}: checkout {commit[:12]}...")
        try:
            subprocess.run(
                ["git", "-C", str(repo_path), "checkout", "-f", commit],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repo_path), "submodule", "update",
                 "--init", "--recursive"],
                capture_output=True,  # no check: algunos repos no tienen submódulos
            )
        except subprocess.CalledProcessError as e:
            log.error(f"[ERROR] {instance_id}/{version}: git checkout falló: {e}")
            result["versions"][version] = "error_checkout"
            continue

        env = {**os.environ, "REPO_PATH": str(repo_path)}
        build_log = log_dir / f"build_{instance_id}_{version}.log"

        # ── Build CodeQL DB ────────────────────────────────────────────────────
        if not codeql_exists:
            db_path_codeql.parent.mkdir(parents=True, exist_ok=True)
            log.info(f"[BUILD] {instance_id}/{version}: codeql database create...")
            try:
                with open(build_log, "w") as blog:
                    subprocess.run([
                        str(CODEQL_BINARY), "database", "create", str(db_path_codeql),
                        "--language=cpp",
                        f"--command=bash {build_script}",
                        "--source-root", str(repo_path),
                        "--threads=2",
                        "--overwrite",
                    ], check=True, env=env, stdout=blog, stderr=blog)
            except subprocess.CalledProcessError:
                log.error(
                    f"[ERROR] {instance_id}/{version}: CodeQL build falló "
                    f"(ver {build_log})"
                )
                result["versions"][version] = "error_codeql_build"
                continue

        # ── Validar build (fichero afectado en src.zip) ────────────────────────
        affected_file = instance.get("affected_file", "")
        if affected_file and not validate_affected_file_in_db(
            db_path_codeql, affected_file, f"{instance_id}/{version}"
        ):
            result["versions"][version] = "invalid_build"
            continue

        # ── Build Coverity (solo si no se salta) ───────────────────────────────
        if not skip_coverity and not coverity_exists:
            db_path_coverity.mkdir(parents=True, exist_ok=True)
            log.info(f"[BUILD] {instance_id}/{version}: cov-build...")
            try:
                subprocess.run([
                    str(COVERITY_HOME / "bin" / "cov-build"),
                    "--dir", str(db_path_coverity),
                    "bash", str(build_script),
                ], check=True, env=env)
            except subprocess.CalledProcessError as e:
                log.error(f"[ERROR] {instance_id}/{version}: cov-build falló: {e}")
                result["versions"][version] = "error_coverity_build"
                continue

        result["versions"][version] = "built"

    return result


# ── Fase B: CodeQL analyze ─────────────────────────────────────────────────────

def analyze_codeql(instance: dict, project: str) -> dict:
    """Fase B: análisis CodeQL sobre DBs ya construidas."""
    instance_id = instance["id"]
    query       = instance.get("codeql_query", "")

    for version in ["V", "S"]:
        db_path   = RESULTS_BASE / "codeql" / project / instance_id / version / "db"
        sarif_out = RESULTS_BASE / "codeql" / project / instance_id / f"{version}.sarif"

        if sarif_out.exists():
            log.info(f"[SKIP_CODEQL] {instance_id}/{version}: SARIF ya existe")
            continue

        if not db_path.exists():
            log.warning(f"[SKIP_CODEQL] {instance_id}/{version}: DB no disponible")
            continue

        sarif_out.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(CODEQL_BINARY), "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={sarif_out}",
            "--threads=4",
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        ]
        if query:
            cmd.append(query)

        log.info(f"[CODEQL] {instance_id}/{version}: analyze...")
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            log.error(f"[ERROR] {instance_id}/{version}: CodeQL analyze falló: {e.stderr.decode()[:200]}")
            return {"instance_id": instance_id, "tool": "codeql", "status": "error"}

    return {"instance_id": instance_id, "tool": "codeql", "status": "done"}


# ── Fase C: Coverity analyze ───────────────────────────────────────────────────

def analyze_coverity(instance: dict, project: str) -> dict:
    """Fase C: análisis Coverity sobre cov_dirs ya construidos."""
    instance_id = instance["id"]

    for version in ["V", "S"]:
        cov_dir  = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"
        json_out = RESULTS_BASE / "coverity" / project / instance_id / f"{version}.json"

        if json_out.exists():
            log.info(f"[SKIP_COVERITY] {instance_id}/{version}: JSON ya existe")
            continue

        if not cov_dir.exists():
            log.warning(f"[SKIP_COVERITY] {instance_id}/{version}: cov_dir no disponible")
            continue

        log.info(f"[COVERITY] {instance_id}/{version}: cov-analyze...")
        try:
            subprocess.run([
                str(COVERITY_HOME / "bin" / "cov-analyze"),
                "--dir", str(cov_dir),
                "--security",
                "--enable", "NULL_RETURNS",
                "--enable", "FORWARD_NULL",
                "--enable", "BUFFER_SIZE",
                "--enable", "OVERRUN",
                "--enable", "INTEGER_OVERFLOW",
                "--enable", "TAINTED_SCALAR",
                "--enable", "USE_AFTER_FREE",
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            log.error(f"[ERROR] {instance_id}/{version}: cov-analyze falló: {e}")
            return {"instance_id": instance_id, "tool": "coverity", "status": "error"}

        json_out.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run([
                str(COVERITY_HOME / "bin" / "cov-format-errors"),
                "--dir", str(cov_dir),
                "--json-output-v8", str(json_out),
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            log.error(f"[ERROR] {instance_id}/{version}: cov-format-errors falló: {e}")
            return {"instance_id": instance_id, "tool": "coverity", "status": "error"}

    return {"instance_id": instance_id, "tool": "coverity", "status": "done"}


# ── Carga de instancias ────────────────────────────────────────────────────────

def load_instances(project_filter: str | None = None) -> list[dict]:
    """Carga todas las instancias evaluables de corpus_b."""
    all_instances: list[dict] = []
    gt_paths = sorted(CORPUS_B_DIR.glob("*/ground_truth.yaml"))

    if not gt_paths:
        log.error(f"No se encontraron ground_truth.yaml en {CORPUS_B_DIR}")
        sys.exit(1)

    for gt_path in gt_paths:
        with open(gt_path) as f:
            gt = yaml.safe_load(f)

        project = gt["project"]

        if project_filter and project != project_filter:
            continue

        for inst in gt.get("instances", []):
            if inst.get("structural_fn", False):
                continue
            if inst.get("needs_manual_verification") and not inst.get("commit_fix"):
                log.warning(f"[SKIP] {inst['id']}: needs_manual_verification sin commit_fix")
                continue
            inst["_project"] = project
            all_instances.append(inst)

    return all_instances


# ── Resumen Fase A ─────────────────────────────────────────────────────────────

def print_phase_a_summary(build_results: dict, all_instances: list,
                           valid_instances: list) -> None:
    log.info("\n" + "=" * 60)
    log.info("RESUMEN FASE A (Builds)")
    log.info("=" * 60)
    by_status: dict[str, list] = {}
    for res in build_results.values():
        for ver, status in res.get("versions", {}).items():
            by_status.setdefault(status, []).append(f"{res['instance_id']}/{ver}")

    for status, entries in sorted(by_status.items()):
        log.info(f"  {status:35s}: {len(entries):3d}")

    log.info(f"\n  Total instancias cargadas : {len(all_instances)}")
    log.info(f"  Instancias con build OK   : {len(valid_instances)}")
    log.info(f"  Instancias saltadas/error : {len(all_instances) - len(valid_instances)}")


# ── Resumen final CodeQL ───────────────────────────────────────────────────────

def print_codeql_summary(all_instances: list) -> None:
    """
    Imprime una tabla de SARIF generados vs esperados por proyecto.
    Útil para verificar completitud al final del runner.
    """
    log.info("\n" + "=" * 60)
    log.info("RESUMEN CODEQL (SARIF generados)")
    log.info("=" * 60)

    by_project: dict[str, dict] = {}
    for inst in all_instances:
        p = inst["_project"]
        if p not in by_project:
            by_project[p] = {"expected": 0, "found": 0, "missing": []}
        for v in ["V", "S"]:
            sarif = RESULTS_BASE / "codeql" / p / inst["id"] / f"{v}.sarif"
            by_project[p]["expected"] += 1
            if sarif.exists():
                by_project[p]["found"] += 1
            else:
                by_project[p]["missing"].append(f"{inst['id']}/{v}")

    total_expected = total_found = 0
    log.info(f"  {'Proyecto':<25} {'Esperados':>9} {'Generados':>9} {'Faltantes':>9}")
    log.info("  " + "-" * 55)
    for proj, data in sorted(by_project.items()):
        total_expected += data["expected"]
        total_found    += data["found"]
        log.info(
            f"  {proj:<25} {data['expected']:>9} {data['found']:>9} "
            f"{data['expected']-data['found']:>9}"
        )
        for miss in data["missing"]:
            log.warning(f"    MISSING: {miss}.sarif")

    log.info("  " + "-" * 55)
    log.info(
        f"  {'TOTAL':<25} {total_expected:>9} {total_found:>9} "
        f"{total_expected-total_found:>9}"
    )

    completeness = total_found / total_expected * 100 if total_expected > 0 else 0
    log.info(f"\n  Completitud: {total_found}/{total_expected} ({completeness:.1f}%)")


# ── Runner principal ───────────────────────────────────────────────────────────

def run_corpus_b(
    project_filter: str | None = None,
    skip_coverity: bool = False,
    phase: str | None = None,
) -> None:
    """Punto de entrada principal del runner."""
    start_time = datetime.now()

    all_instances = load_instances(project_filter)
    log.info(f"\nCorpus B: {len(all_instances)} instancias evaluables")
    log.info(f"Proyectos: {sorted(set(i['_project'] for i in all_instances))}")
    if project_filter:
        log.info(f"Filtro activo: --project {project_filter}")
    if skip_coverity:
        log.info("Modo: --skip-coverity (solo CodeQL)")

    # Clonar repositorios
    projects_needed = sorted(set(i["_project"] for i in all_instances))
    for proj in projects_needed:
        try:
            clone_if_needed(proj)
        except Exception as e:
            log.error(f"No se pudo clonar {proj}: {e}")

    build_results: dict[str, dict] = {}
    valid_instances: list[dict] = []

    if phase in (None, "A"):
        # ── FASE A — Builds paralelos ──────────────────────────────────────────
        log.info("\n=== FASE A: Compilación paralela ===")
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=MAX_BUILD_WORKERS) as ex:
            futures = {
                ex.submit(
                    build_both_tools, inst, inst["_project"], skip_coverity
                ): inst["id"]
                for inst in all_instances
            }
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    build_results[r["instance_id"]] = r
                    versions_str = ", ".join(
                        f"{v}={s}" for v, s in r["versions"].items()
                    )
                    log.info(f"  [BUILD] {r['instance_id']} [{versions_str}]")
                except Exception as e:
                    inst_id = futures[f]
                    log.error(f"  [EXCEPTION] {inst_id}: {e}")
                    build_results[inst_id] = {"instance_id": inst_id, "versions": {}}

        valid_instances = [
            inst for inst in all_instances
            if all(
                build_results.get(inst["id"], {}).get("versions", {}).get(v)
                in ("built", "skipped")
                for v in ["V", "S"]
            )
        ]

        print_phase_a_summary(build_results, all_instances, valid_instances)

        if not valid_instances:
            log.error("Ninguna instancia tiene build válido. Revisar build scripts.")
            return

        # Persistir resultados de Fase A
        RESULTS_BASE.mkdir(parents=True, exist_ok=True)
        phase_a_out = RESULTS_BASE / "phase_a_results.json"
        with open(phase_a_out, "w") as f:
            json.dump(build_results, f, indent=2)
        log.info(f"\n  Resultados fase A guardados en: {phase_a_out}")

        if phase == "A":
            return

    else:
        # Saltar fase A: cargar resultados previos si existen
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
            log.info(f"Fase A cargada desde {phase_a_out}: {len(valid_instances)} instancias válidas")
        else:
            log.warning("No hay resultados de fase A previos. Ejecutando con todas las instancias.")
            valid_instances = all_instances

    if phase in (None, "B"):
        # ── FASE B — CodeQL paralelo ───────────────────────────────────────────
        log.info("\n=== FASE B: Análisis CodeQL paralelo ===")
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=MAX_CODEQL_WORKERS) as ex:
            futures = {
                ex.submit(analyze_codeql, inst, inst["_project"]): inst["id"]
                for inst in valid_instances
            }
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    icon = "✓" if r["status"] == "done" else "✗"
                    log.info(f"  {icon} CodeQL: {r['instance_id']} [{r['status']}]")
                except Exception as e:
                    inst_id = futures[f]
                    log.error(f"  [EXCEPTION] CodeQL {inst_id}: {e}")

        print_codeql_summary(valid_instances)

        if phase == "B":
            return

    if phase in (None, "C") and not skip_coverity:
        # ── FASE C — Coverity paralelo ─────────────────────────────────────────
        log.info("\n=== FASE C: Análisis Coverity paralelo ===")
        with concurrent.futures.ProcessPoolExecutor(
                max_workers=MAX_COVERITY_WORKERS) as ex:
            futures = {
                ex.submit(analyze_coverity, inst, inst["_project"]): inst["id"]
                for inst in valid_instances
            }
            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    icon = "✓" if r["status"] == "done" else "✗"
                    log.info(f"  {icon} Coverity: {r['instance_id']} [{r['status']}]")
                except Exception as e:
                    inst_id = futures[f]
                    log.error(f"  [EXCEPTION] Coverity {inst_id}: {e}")
    elif skip_coverity and phase in (None, "C"):
        log.info("\n[SKIP] Fase C omitida (--skip-coverity).")
        log.info("       Coverity pendiente de licencia Linux — ver corpus_b/results/PENDIENTE_COVERITY.md")

    elapsed = datetime.now() - start_time
    log.info(f"\n=== Corpus B completado en {elapsed} ===")
    log.info(f"Resultados en: {RESULTS_BASE}")
    log.info("Siguiente paso: python shared/deduplicator/dedup_findings.py --corpus b")


# ── Entrypoint ─────────────────────────────────────────────────────────────────

def main() -> None:
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
        help="Ejecutar solo CodeQL, omitir Coverity (pendiente de licencia Linux)",
    )
    parser.add_argument(
        "--phase",
        choices=["A", "B", "C"],
        help="Ejecutar solo una fase (A=build, B=codeql, C=coverity)",
    )
    parser.add_argument(
        "--only-coverity",
        action="store_true",
        help="Ejecutar solo la fase C (Coverity), para cuando llegue la licencia",
    )
    args = parser.parse_args()

    # Inicializar logging (después de que RESULTS_BASE esté configurado)
    global log
    log = _setup_logging()

    log.info("=" * 60)
    log.info("BENCHMARK SAST — Corpus B (EMBOSS Shen et al. ISSTA 2025)")
    log.info("=" * 60)

    # --only-coverity equivale a --phase C
    if args.only_coverity:
        args.phase = "C"
        args.skip_coverity = False

    # Validar herramientas
    if not CODEQL_BINARY.exists():
        log.error(f"CodeQL no encontrado en {CODEQL_BINARY}")
        log.error("  Instalar: https://github.com/github/codeql-action/releases")
        log.error("  O configurar CODEQL_BINARY en .env.benchmark")
        sys.exit(1)

    if not args.skip_coverity and not (COVERITY_HOME / "bin" / "cov-build").exists():
        log.warning(f"Coverity no encontrado en {COVERITY_HOME}")
        log.warning("  Activando --skip-coverity implícito.")
        log.warning("  Para activar Coverity: bash corpus_b/scripts/install_coverity_linux.sh <installer>")
        args.skip_coverity = True

    run_corpus_b(
        project_filter=args.project,
        skip_coverity=args.skip_coverity,
        phase=args.phase,
    )


if __name__ == "__main__":
    main()
