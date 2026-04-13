#!/usr/bin/env python3
"""
runner/coverity/run_coverity.py
================================
Ejecuta Coverity (cov-build + cov-analyze + cov-format-errors) sobre el
par (commit_vulnerable, commit_fix) de cada instancia del ground truth.

Salida: results/raw/coverity/{project}/{cve_id}/{V|S}.json
        (formato: Coverity JSON v8, exportado con cov-format-errors --json-v8)

NOTAS SOBRE EL ENTORNO:
  - Requiere Coverity Connect o Coverity Analysis local (cov-build, cov-analyze,
    cov-format-errors en el PATH o en --coverity-home).
  - La licencia se asume disponible en el host (Cipherbit la tiene corporativa).
  - La integración CI usa COVERITY_TOKEN + COVERITY_URL cuando está disponible.

USO:
    python run_coverity.py \
        --ground-truth ../../corpus/mbedtls/ground_truth.yaml \
        --repo-path /tmp/repos/mbedtls \
        --output-dir ../../results/raw/coverity/mbedtls \
        --coverity-home /opt/coverity \
        [--checkers-config ../../config/coverity_checkers.conf] \
        [--threads 4] \
        [--dry-run]
"""

import argparse
import json
import logging
import os
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
# Checkers de Coverity relevantes para las CWE del ground truth
# Referencia: Coverity Static Analysis Checker Reference v2023.6
# ---------------------------------------------------------------------------
COVERITY_CHECKERS = {
    "CWE-476": [
        "NULL_RETURNS",           # Dereferencia de puntero potencialmente nulo
        "FORWARD_NULL",           # Nulo propagado a través de llamadas
    ],
    "CWE-190": [
        "INTEGER_OVERFLOW",       # Desbordamiento aritmético
        "NEGATIVE_RETURNS",       # Valor de retorno negativo usado como tamaño
        "OVERFLOW_BEFORE_WIDEN",  # Overflow antes del cast a tipo mayor
    ],
    "CWE-125": [
        "BUFFER_SIZE",            # Acceso fuera de bounds (lectura)
        "OVERRUN",                # Out-of-bounds read
    ],
    "CWE-122": [
        "BUFFER_SIZE",
        "OVERRUN",
        "HEAP_OVERFLOW",          # Heap buffer overflow
    ],
    "CWE-121": [
        "STACK_USE_AFTER_RETURN", # Stack overflow clásico
        "BUFFER_SIZE",
    ],
    "CWE-416": [
        "USE_AFTER_FREE",         # Uso de memoria liberada
        "RESOURCE_LEAK",          # Recursos no liberados (correlacionado)
    ],
}

# Todos los checkers únicos del benchmark
ALL_CHECKERS = sorted(set(c for cs in COVERITY_CHECKERS.values() for c in cs))


def parse_args():
    p = argparse.ArgumentParser(description="Coverity runner para benchmark SAST")
    p.add_argument("--ground-truth", required=True)
    p.add_argument("--repo-path", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--coverity-home", default=os.environ.get("COVERITY_HOME", "/opt/cov-analysis"))
    p.add_argument("--checkers-config", default=None,
                   help="Fichero .conf con checkers adicionales (opcional)")
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--skip-existing", action="store_true")
    p.add_argument("--only-cve", nargs="+", default=None)
    return p.parse_args()


def load_ground_truth(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def cov_bin(coverity_home: str, tool: str) -> str:
    return str(Path(coverity_home) / "bin" / tool)


def run_cmd(cmd, cwd=None, dry_run=False, env=None):
    cmd_str = " ".join(str(c) for c in cmd)
    log.debug(f"CMD: {cmd_str}")
    if dry_run:
        print(f"[DRY-RUN] {cmd_str}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    merged_env = {**os.environ, **(env or {})}
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=merged_env)


def git_checkout(repo_path, commit, dry_run=False):
    run_cmd(["git", "checkout", "--quiet", commit], cwd=repo_path, dry_run=dry_run)
    run_cmd(["git", "clean", "-fdx", "--quiet"], cwd=repo_path, dry_run=dry_run)


def build_coverity_db(
    coverity_home: str, repo_path: str, idir: str,
    build_cmd: str, threads: int, dry_run: bool
) -> bool:
    """
    cov-build intercepta el compilador durante la build y crea el idir.
    Para proyectos cmake: genera primero compile_commands.json y luego
    usa cov-build --emit-complementary-info con make.
    """
    idir_path = Path(idir)
    if idir_path.exists():
        import shutil; shutil.rmtree(idir, ignore_errors=True)

    # 1. Generar Makefile desde cmake si aplica
    if "cmake" in build_cmd:
        build_dir = Path(repo_path) / "build"
        build_dir.mkdir(exist_ok=True)
        r = run_cmd(
            ["cmake", "-DCMAKE_BUILD_TYPE=Debug", ".."],
            cwd=str(build_dir), dry_run=dry_run
        )
        if r.returncode != 0 and not dry_run:
            log.error("cmake configure falló")
            return False
        # Coverity intercepta make en build_dir
        cov_build_cmd = [
            cov_bin(coverity_home, "cov-build"),
            "--dir", idir,
            "--emit-complementary-info",
            "make", f"-j{threads}",
        ]
        result = run_cmd(cov_build_cmd, cwd=str(build_dir), dry_run=dry_run)
    else:
        # autoconf: bear no aplica con Coverity; usamos cov-build directamente
        run_cmd(["make", "clean"], cwd=repo_path, dry_run=dry_run)
        cov_build_cmd = [
            cov_bin(coverity_home, "cov-build"),
            "--dir", idir,
            "make", f"-j{threads}",
        ]
        result = run_cmd(cov_build_cmd, cwd=repo_path, dry_run=dry_run)

    if result.returncode != 0 and not dry_run:
        log.error(f"cov-build falló: {result.stderr[:1000]}")
        return False
    return True


def run_coverity_analyze(
    coverity_home: str, idir: str,
    threads: int, checkers_config: str | None, dry_run: bool
) -> bool:
    """
    cov-analyze: activa solo los checkers relevantes para las CWE del GT.
    Esto reduce el ruido y hace la comparación más controlada.
    """
    cmd = [
        cov_bin(coverity_home, "cov-analyze"),
        "--dir", idir,
        f"--jobs={threads}",
        "--security",          # Activa el security checker bundle
        "--enable-fnptr",      # Análisis interprocedural via punteros a función
        "--enable-virtual",    # C++ virtual dispatch
        "--concurrency",       # Data race detection (reduce FP en C)
        # Activar solo los checkers del GT para contener el volumen de findings
        "--all",               # Base: todos; luego se filtran en el evaluador
        # Alternativamente, activar checkers específicos:
        # *[f"--enable={c}" for c in ALL_CHECKERS],
    ]
    if checkers_config:
        cmd += ["--config", checkers_config]

    start = time.monotonic()
    result = run_cmd(cmd, dry_run=dry_run)
    elapsed = time.monotonic() - start

    if result.returncode != 0 and not dry_run:
        log.error(f"cov-analyze falló: {result.stderr[:1000]}")
        return False

    log.info(f"cov-analyze completado en {elapsed:.1f}s")
    return True


def export_coverity_json(
    coverity_home: str, idir: str, json_out: str, dry_run: bool
) -> bool:
    """
    Exporta los resultados en formato JSON v8 (parseable y estable).
    JSON v8 incluye: checker, subcategory, file, function, line, mergeKey,
    impact, cwe.
    """
    cmd = [
        cov_bin(coverity_home, "cov-format-errors"),
        "--dir", idir,
        "--json-output-v8", json_out,
        "--include-files", ".*\\.(c|cpp|h|hpp)$",   # Solo código fuente, no generado
    ]
    result = run_cmd(cmd, dry_run=dry_run)
    if result.returncode != 0 and not dry_run:
        log.error(f"cov-format-errors falló: {result.stderr[:500]}")
        return False
    log.info(f"JSON exportado → {json_out}")
    return True


def count_findings(json_path: str) -> int:
    """Cuenta findings en el JSON de Coverity para logging."""
    if not Path(json_path).exists():
        return -1
    with open(json_path) as f:
        data = json.load(f)
    return len(data.get("issues", []))


def process_instance(
    instance: dict, gt: dict, repo_path: str,
    output_dir: str, coverity_home: str,
    checkers_config: str | None, threads: int,
    dry_run: bool, skip_existing: bool
):
    cve_id = instance["cve"]
    inst_id = instance["id"]
    log.info(f"\n{'='*60}")
    log.info(f"Procesando: {inst_id}")

    if instance.get("structural_fn"):
        log.info(f"  → FN estructural: {cve_id} — omitiendo análisis Coverity")
        _write_structural_fn_marker(output_dir, cve_id, instance)
        return

    build_cmd = gt.get("compile_commands_generator", "cmake ..")
    inst_dir = Path(output_dir) / cve_id
    inst_dir.mkdir(parents=True, exist_ok=True)

    for version_label, commit in [
        ("V", instance["commit_vulnerable"]),
        ("S", instance["commit_fix"]),
    ]:
        json_out = str(inst_dir / f"{version_label}.json")
        meta_out = str(inst_dir / f"{version_label}.meta.json")

        if skip_existing and Path(json_out).exists():
            log.info(f"  [{version_label}] Existe, saltando.")
            continue

        log.info(f"  [{version_label}] Checkout → {commit[:12]}")
        git_checkout(repo_path, commit, dry_run)

        idir = str(inst_dir / f"idir_{version_label}")
        log.info(f"  [{version_label}] cov-build → {idir}")
        ok = build_coverity_db(coverity_home, repo_path, idir, build_cmd, threads, dry_run)
        if not ok:
            _write_error_marker(inst_dir, cve_id, version_label, "cov_build_failed")
            continue

        log.info(f"  [{version_label}] cov-analyze")
        ok = run_coverity_analyze(coverity_home, idir, threads, checkers_config, dry_run)
        if not ok:
            _write_error_marker(inst_dir, cve_id, version_label, "cov_analyze_failed")
            continue

        log.info(f"  [{version_label}] Exportando JSON")
        ok = export_coverity_json(coverity_home, idir, json_out, dry_run)
        if not ok:
            _write_error_marker(inst_dir, cve_id, version_label, "export_failed")
            continue

        n = count_findings(json_out)
        log.info(f"  [{version_label}] Findings exportados: {n}")

        meta = {
            "tool": "coverity",
            "project": gt["project"],
            "cve": cve_id,
            "cwe": instance["cwe"],
            "cwe_family": instance["cwe_family"],
            "version": version_label,
            "commit": commit,
            "affected_file": instance["affected_file"],
            "structural_fn": instance.get("structural_fn", False),
            "json_path": json_out,
            "finding_count_raw": n,
        }
        if not dry_run:
            with open(meta_out, "w") as f:
                json.dump(meta, f, indent=2)

    log.info(f"  Instancia {inst_id} completada.")


def _write_structural_fn_marker(output_dir, cve_id, instance):
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


def _write_error_marker(inst_dir, cve_id, version, reason):
    with open(inst_dir / f"{version}.error.json", "w") as f:
        json.dump({"cve": cve_id, "version": version, "error": reason}, f, indent=2)


def main():
    args = parse_args()
    gt = load_ground_truth(args.ground_truth)

    if not Path(args.repo_path).exists():
        log.info(f"Clonando {gt['repo_url']} en {args.repo_path}")
        subprocess.run(["git", "clone", gt["repo_url"], args.repo_path], check=True)

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    instances = gt["instances"]
    if args.only_cve:
        instances = [i for i in instances if i["cve"] in args.only_cve]

    for instance in instances:
        process_instance(
            instance, gt, args.repo_path, args.output_dir,
            args.coverity_home, args.checkers_config,
            args.threads, args.dry_run, args.skip_existing,
        )

    log.info("\n✓ Runner Coverity completado.")


if __name__ == "__main__":
    main()
