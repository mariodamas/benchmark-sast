#!/usr/bin/env python3
"""
runner/codeql/run_codeql.py
===========================
Ejecuta CodeQL sobre el par (commit_vulnerable, commit_fix) de cada instancia
del ground truth. Para cada instancia:
  1. Hace checkout del commit vulnerable (V)
  2. Crea la base de datos CodeQL
  3. Ejecuta las queries de seguridad
  4. Exporta los resultados en SARIF
  5. Repite para el commit sano (S)

Salida: results/raw/codeql/{project}/{cve_id}/{V|S}.sarif

USO:
    python run_codeql.py \
        --ground-truth ../../corpus/mbedtls/ground_truth.yaml \
        --repo-path /tmp/repos/mbedtls \
        --output-dir ../../results/raw/codeql/mbedtls \
        --codeql-binary /opt/codeql/codeql \
        [--suite security-extended] \
        [--threads 4] \
        [--dry-run]
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
CODEQL_SUITE_DEFAULT = "security-extended"
# Queries adicionales para C/C++ embebido — cubre las CWE del ground truth
CODEQL_QUERY_PACKS = [
    "codeql/cpp-queries:Security/CWE/CWE-119",   # Buffer Not Checked
    "codeql/cpp-queries:Security/CWE/CWE-125",   # OOB Read
    "codeql/cpp-queries:Security/CWE/CWE-190",   # Integer Overflow
    "codeql/cpp-queries:Security/CWE/CWE-416",   # Use After Free
    "codeql/cpp-queries:Security/CWE/CWE-476",   # NULL Ptr Deref
]
DB_RAM_MB = 4096  # RAM máxima para la BD CodeQL


def parse_args():
    p = argparse.ArgumentParser(description="CodeQL runner para benchmark SAST")
    p.add_argument("--ground-truth", required=True, help="Ruta al ground_truth.yaml")
    p.add_argument("--repo-path", required=True, help="Directorio del repo git clonado")
    p.add_argument("--output-dir", required=True, help="Directorio de salida SARIF")
    p.add_argument("--codeql-binary", default="codeql", help="Ruta al binario codeql")
    p.add_argument("--suite", default=CODEQL_SUITE_DEFAULT, help="Suite de queries")
    p.add_argument("--threads", type=int, default=4, help="Threads para CodeQL")
    p.add_argument("--dry-run", action="store_true", help="No ejecutar, solo imprimir comandos")
    p.add_argument("--skip-existing", action="store_true", help="Saltar CVEs ya procesados")
    p.add_argument(
        "--only-cve", nargs="+", default=None,
        help="Lista de CVE IDs a procesar (default: todos)"
    )
    return p.parse_args()


def load_ground_truth(path: str) -> dict:
    with open(path) as f:
        gt = yaml.safe_load(f)
    log.info(f"Ground truth cargado: {gt['project']} — {len(gt['instances'])} instancias")
    return gt


def run_cmd(cmd: list[str], cwd: str = None, dry_run: bool = False) -> subprocess.CompletedProcess:
    cmd_str = " ".join(str(c) for c in cmd)
    log.debug(f"CMD: {cmd_str}")
    if dry_run:
        print(f"[DRY-RUN] {cmd_str}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        log.error(f"STDERR: {result.stderr[:2000]}")
    return result


def git_checkout(repo_path: str, commit: str, dry_run: bool = False):
    """Checkout limpio al commit especificado."""
    run_cmd(["git", "checkout", "--quiet", commit], cwd=repo_path, dry_run=dry_run)
    run_cmd(["git", "clean", "-fdx", "--quiet"], cwd=repo_path, dry_run=dry_run)


def generate_compile_commands(repo_path: str, build_cmd: str, dry_run: bool = False) -> bool:
    """
    Genera compile_commands.json usando el comando de build del ground truth.
    Para cmake: cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    Para autoconf: bear -- make
    """
    build_dir = Path(repo_path) / "build"
    build_dir.mkdir(exist_ok=True)

    if "cmake" in build_cmd:
        run_cmd(["cmake", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", ".."],
                cwd=str(build_dir), dry_run=dry_run)
        # Enlace simbólico para que CodeQL encuentre compile_commands.json en la raíz
        cc_src = build_dir / "compile_commands.json"
        cc_dst = Path(repo_path) / "compile_commands.json"
        if not dry_run and cc_src.exists() and not cc_dst.exists():
            cc_dst.symlink_to(cc_src)
    elif "bear" in build_cmd:
        run_cmd(["make", "clean"], cwd=repo_path, dry_run=dry_run)
        run_cmd(build_cmd.split(), cwd=repo_path, dry_run=dry_run)
    else:
        log.warning(f"Build command no reconocido: {build_cmd}")
        return False
    return True


def create_codeql_db(
    codeql_bin: str, repo_path: str, db_path: str,
    threads: int, dry_run: bool = False
) -> bool:
    """Crea la base de datos CodeQL para C/C++."""
    if Path(db_path).exists():
        shutil.rmtree(db_path, ignore_errors=True)

    cmd = [
        codeql_bin, "database", "create",
        db_path,
        "--language=cpp",
        f"--source-root={repo_path}",
        f"--threads={threads}",
        f"--ram={DB_RAM_MB}",
        "--overwrite",
        # El build command se infiere de compile_commands.json cuando existe
        "--build-mode=none" if (Path(repo_path) / "compile_commands.json").exists()
                            else f"--command=make -j{threads}",
    ]
    result = run_cmd(cmd, cwd=repo_path, dry_run=dry_run)
    if result.returncode != 0:
        log.error(f"Error creando DB CodeQL en {db_path}")
        return False
    log.info(f"DB CodeQL creada: {db_path}")
    return True


def run_codeql_analysis(
    codeql_bin: str, db_path: str, sarif_out: str,
    suite: str, threads: int, dry_run: bool = False
) -> bool:
    """Ejecuta las queries y exporta SARIF."""
    cmd = [
        codeql_bin, "database", "analyze",
        db_path,
        f"--format=sarif-latest",
        f"--output={sarif_out}",
        f"--threads={threads}",
        f"--ram={DB_RAM_MB}",
        suite,      # e.g. "security-extended"
        # Queries adicionales específicas para las CWE del ground truth
        *CODEQL_QUERY_PACKS,
    ]
    start = time.monotonic()
    result = run_cmd(cmd, dry_run=dry_run)
    elapsed = time.monotonic() - start

    if result.returncode != 0:
        log.error(f"Error en análisis CodeQL → {sarif_out}")
        return False

    log.info(f"Análisis completado en {elapsed:.1f}s → {sarif_out}")

    # Anotar tiempo de ejecución dentro del SARIF (extensión propia del benchmark)
    if not dry_run:
        _annotate_sarif_timing(sarif_out, elapsed)
    return True


def _annotate_sarif_timing(sarif_path: str, elapsed_s: float):
    """Añade timing como propiedad al SARIF para métricas de benchmark."""
    with open(sarif_path) as f:
        sarif = json.load(f)
    sarif.setdefault("properties", {})["benchmark_analysis_seconds"] = round(elapsed_s, 2)
    with open(sarif_path, "w") as f:
        json.dump(sarif, f, indent=2)


def process_instance(
    instance: dict, gt: dict, repo_path: str,
    output_dir: str, codeql_bin: str, suite: str,
    threads: int, dry_run: bool, skip_existing: bool
):
    """Procesa una instancia del ground truth (V + S)."""
    cve_id = instance["cve"]
    inst_id = instance["id"]
    log.info(f"\n{'='*60}")
    log.info(f"Procesando: {inst_id}")

    if instance.get("structural_fn"):
        log.info(f"  → FN estructural documentado: {cve_id} — saltando ejecución SAST")
        _write_structural_fn_marker(output_dir, cve_id, instance)
        return

    build_cmd = gt.get("compile_commands_generator", "cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..")
    inst_dir = Path(output_dir) / cve_id
    inst_dir.mkdir(parents=True, exist_ok=True)

    for version_label, commit in [
        ("V", instance["commit_vulnerable"]),
        ("S", instance["commit_fix"]),
    ]:
        sarif_out = str(inst_dir / f"{version_label}.sarif")
        meta_out = str(inst_dir / f"{version_label}.meta.json")

        if skip_existing and Path(sarif_out).exists():
            log.info(f"  [{version_label}] Ya existe, saltando: {sarif_out}")
            continue

        log.info(f"  [{version_label}] Checkout → {commit[:12]}")
        git_checkout(repo_path, commit, dry_run)

        log.info(f"  [{version_label}] Generando compile_commands.json")
        generate_compile_commands(repo_path, build_cmd, dry_run)

        db_path = str(inst_dir / f"db_{version_label}")
        log.info(f"  [{version_label}] Creando DB CodeQL")
        ok = create_codeql_db(codeql_bin, repo_path, db_path, threads, dry_run)
        if not ok:
            log.error(f"  [{version_label}] FALLO en DB — instancia marcada como ERROR")
            _write_error_marker(inst_dir, cve_id, version_label, "db_creation_failed")
            continue

        log.info(f"  [{version_label}] Ejecutando análisis")
        ok = run_codeql_analysis(codeql_bin, db_path, sarif_out, suite, threads, dry_run)
        if not ok:
            _write_error_marker(inst_dir, cve_id, version_label, "analysis_failed")
            continue

        # Metadatos de la instancia para el evaluador
        meta = {
            "tool": "codeql",
            "project": gt["project"],
            "cve": cve_id,
            "cwe": instance["cwe"],
            "cwe_family": instance["cwe_family"],
            "version": version_label,
            "commit": commit,
            "affected_file": instance["affected_file"],
            "structural_fn": instance.get("structural_fn", False),
            "sarif_path": sarif_out,
        }
        if not dry_run:
            with open(meta_out, "w") as f:
                json.dump(meta, f, indent=2)

    log.info(f"  Instancia {inst_id} completada.")


def _write_structural_fn_marker(output_dir: str, cve_id: str, instance: dict):
    marker = Path(output_dir) / cve_id / "structural_fn.json"
    marker.parent.mkdir(parents=True, exist_ok=True)
    with open(marker, "w") as f:
        json.dump({
            "type": "structural_fn",
            "cve": cve_id,
            "cwe": instance["cwe"],
            "reason": instance.get("notes", ""),
            "sast_detectable": False,
        }, f, indent=2)


def _write_error_marker(inst_dir: Path, cve_id: str, version: str, reason: str):
    with open(inst_dir / f"{version}.error.json", "w") as f:
        json.dump({"cve": cve_id, "version": version, "error": reason}, f, indent=2)


def main():
    args = parse_args()
    gt = load_ground_truth(args.ground_truth)

    repo_path = args.repo_path
    if not Path(repo_path).exists():
        log.info(f"Clonando repositorio en {repo_path} ...")
        subprocess.run(["git", "clone", gt["repo_url"], repo_path], check=True)

    output_dir = args.output_dir
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    instances = gt["instances"]
    if args.only_cve:
        instances = [i for i in instances if i["cve"] in args.only_cve]
        log.info(f"Filtrando a {len(instances)} instancias: {args.only_cve}")

    log.info(f"\nTotal instancias a procesar: {len(instances)}")
    log.info(f"  FN estructurales (excluidos de SAST): "
             f"{sum(1 for i in instances if i.get('structural_fn'))}")
    log.info(f"  Instancias evaluables:                "
             f"{sum(1 for i in instances if not i.get('structural_fn'))}")

    for instance in instances:
        process_instance(
            instance, gt, repo_path, output_dir,
            args.codeql_binary, args.suite, args.threads,
            args.dry_run, args.skip_existing,
        )

    log.info("\n✓ Runner CodeQL completado.")
    log.info(f"  Resultados en: {output_dir}")


if __name__ == "__main__":
    main()
