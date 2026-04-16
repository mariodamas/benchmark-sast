"""
Windows-native Coverity runner for corpus_b.

Goal:
- Run Coverity 100% on Windows host (no WSL dependency)
- Produce JSON outputs compatible with existing classification flow:
  corpus_b/results/coverity/<project>/<instance_id>/<V|S>.json

Usage examples (PowerShell, from repo root):
  python corpus_b/runner/run_coverity_windows.py --project raylib
  python corpus_b/runner/run_coverity_windows.py --id EPK2-DEFECT-004 --version both --classify
  python corpus_b/runner/run_coverity_windows.py --project raylib --build-only
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


DEFAULT_COVERITY_HOME = (
    r"C:\Users\EXTmdamas\AppData\Local\Programs\Coverity\Coverity Static Analysis"
)
DEFAULT_REPOS_BASE = r"C:\Users\EXTmdamas\repos_b_windows"
DEFAULT_RESULTS_BASE = r"corpus_b\results"
DEFAULT_BUILD_CONFIG = r"corpus_b\runner\build_scripts_windows\build_commands_windows.json"
DEFAULT_CORPUS_DIR = r"corpus_b\corpus"


COVERITY_CHECKERS = [
    "--enable",
    "NULL_RETURNS",
    "--enable",
    "FORWARD_NULL",
    "--enable",
    "BUFFER_SIZE",
    "--enable",
    "OVERRUN",
    "--enable",
    "INTEGER_OVERFLOW",
    "--enable",
    "TAINTED_SCALAR",
    "--enable",
    "USE_AFTER_FREE",
    "--enable",
    "STRING_OVERFLOW",
]


def resolve_cov_bin(coverity_home: Path, name: str) -> Path:
    base = coverity_home if coverity_home.name.lower() == "bin" else coverity_home / "bin"
    exe = base / f"{name}.exe"
    plain = base / name
    if exe.exists():
        return exe
    if plain.exists():
        return plain
    return exe


def run_cmd(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def find_vsdevcmd() -> Path | None:
    """Return VsDevCmd path if available, else None."""
    candidates = [
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def to_short_path(path: Path) -> str:
    """Return 8.3 short path on Windows, fallback to original string."""
    try:
        if os.name != "nt":
            return str(path)
        buf_len = 32768
        out_buf = ctypes.create_unicode_buffer(buf_len)
        rc = ctypes.windll.kernel32.GetShortPathNameW(str(path), out_buf, buf_len)
        if rc > 0:
            return out_buf.value
    except Exception:
        pass
    return str(path)


def load_instances(corpus_dir: Path, project_filter: str | None = None, instance_id: str | None = None) -> list[tuple[dict, str]]:
    out: list[tuple[dict, str]] = []
    for gt_path in sorted(corpus_dir.glob("*/ground_truth.yaml")):
        with open(gt_path, encoding="utf-8") as f:
            gt = yaml.safe_load(f)
        project = gt["project"]
        if project_filter and project != project_filter:
            continue

        for inst in gt.get("instances", []):
            if inst.get("structural_fn", False):
                continue
            if inst.get("needs_manual_verification", False):
                continue
            if instance_id and inst.get("id") != instance_id:
                continue
            out.append((inst, project))

    return out


def load_build_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Build config not found: {path}")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_build_cmd(config: dict, project: str, version: str) -> str:
    project_cfg = config.get(project, {})
    if isinstance(project_cfg, str):
        return project_cfg
    if not isinstance(project_cfg, dict):
        return "__NOT_CONFIGURED__"
    return project_cfg.get(version, project_cfg.get("default", "__NOT_CONFIGURED__"))


def checkout_commit(repo_path: Path, commit: str) -> None:
    run_cmd(["git", "-C", str(repo_path), "checkout", "-f", commit])
    subprocess.run(["git", "-C", str(repo_path), "submodule", "update", "--init", "--recursive"], check=False)


def build_coverity(
    *,
    coverity_home: Path,
    repos_base: Path,
    results_base: Path,
    build_config: dict,
    instance: dict,
    project: str,
    version: str,
    keep_existing: bool,
) -> tuple[bool, str, Path]:
    instance_id = instance["id"]
    commit = instance.get("commit_vulnerable" if version == "V" else "commit_fix")
    if not commit:
        return False, "missing_commit", Path()

    repo_path = repos_base / project
    if not repo_path.exists():
        return False, f"repo_missing:{repo_path}", Path()

    cov_dir = results_base / "coverity" / project / instance_id / version / "cov_dir"
    if cov_dir.exists() and keep_existing:
        return True, "skipped_existing_cov_dir", cov_dir

    if cov_dir.exists() and not keep_existing:
        shutil.rmtree(cov_dir, ignore_errors=True)
    cov_dir.mkdir(parents=True, exist_ok=True)

    build_cmd = get_build_cmd(build_config, project, version)
    if build_cmd == "__NOT_CONFIGURED__":
        return False, f"build_not_configured:{project}", cov_dir

    checkout_commit(repo_path, commit)

    cov_build = resolve_cov_bin(coverity_home, "cov-build")
    env = {
        **os.environ,
        "REPO_PATH": str(repo_path),
        "INSTANCE_ID": instance_id,
        "AFFECTED_FILE": instance.get("affected_file", ""),
        "COVERITY_VERSION": version,
        "TARGET_COMMIT": commit,
    }
    vsdevcmd = find_vsdevcmd()
    if vsdevcmd:
        vsdevcmd_cmd = to_short_path(vsdevcmd)
        full_build_cmd = (
            f'call {vsdevcmd_cmd} -arch=x64 -host_arch=x64 >nul && {build_cmd}'
        )
    else:
        full_build_cmd = build_cmd

    cmd = [str(cov_build), "--dir", str(cov_dir), "cmd", "/c", full_build_cmd]

    try:
        run_cmd(cmd, cwd=repo_path, env=env)
    except subprocess.CalledProcessError as e:
        # Some projects can return non-zero while still emitting valid TUs.
        emit_dir = cov_dir / "emit"
        has_emits = emit_dir.exists() and any(emit_dir.rglob("*.tu"))
        if has_emits:
            return True, f"cov_build_nonzero_but_emits:{e.returncode}", cov_dir
        return False, f"cov_build_failed:{e.returncode}", cov_dir

    return True, "built", cov_dir


def analyze_coverity(
    *,
    coverity_home: Path,
    results_base: Path,
    instance: dict,
    project: str,
    version: str,
) -> tuple[bool, str, Path]:
    instance_id = instance["id"]
    cov_dir = results_base / "coverity" / project / instance_id / version / "cov_dir"
    json_out = results_base / "coverity" / project / instance_id / f"{version}.json"

    if not cov_dir.exists():
        return False, f"cov_dir_missing:{cov_dir}", json_out

    json_out.parent.mkdir(parents=True, exist_ok=True)

    cov_analyze = resolve_cov_bin(coverity_home, "cov-analyze")
    cov_errors = resolve_cov_bin(coverity_home, "cov-format-errors")

    try:
        run_cmd([str(cov_analyze), "--dir", str(cov_dir), "--security", *COVERITY_CHECKERS])
    except subprocess.CalledProcessError as e:
        return False, f"cov_analyze_failed:{e.returncode}", json_out

    try:
        run_cmd([str(cov_errors), "--dir", str(cov_dir), "--json-output-v8", str(json_out)])
    except subprocess.CalledProcessError as e:
        return False, f"cov_export_failed:{e.returncode}", json_out

    return True, "analyzed", json_out


def classify_instance(instance: dict, project: str, results_base: Path) -> dict:
    instance_id = instance["id"]
    affected_file = instance.get("affected_file", "")
    cwe_id = instance.get("cwe_id", "")
    cwe_family = instance.get("cwe_family", "")

    cwe_to_checker = {
        "null-deref": ["NULL_RETURNS", "FORWARD_NULL"],
        "buffer-overflow": ["BUFFER_SIZE", "OVERRUN", "STRING_OVERFLOW"],
        "integer-overflow": ["INTEGER_OVERFLOW", "TAINTED_SCALAR"],
        "format-string": ["STRING_OVERFLOW", "TAINTED_SCALAR"],
    }
    expected = set(cwe_to_checker.get(cwe_family, []))

    out = {
        "id": instance_id,
        "project": project,
        "classification": "UNKNOWN",
        "cwe_id": cwe_id,
        "cwe_family": cwe_family,
        "affected_file": affected_file,
    }

    found = {}
    for version in ("V", "S"):
        p = results_base / "coverity" / project / instance_id / f"{version}.json"
        if not p.exists():
            out[version] = {"found": None, "issue_count": 0}
            found[version] = None
            continue

        with open(p, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        issues = []
        for issue in data.get("issues", []):
            file_a = issue.get("strippedMainEventFilePathname", "")
            file_b = issue.get("mainEventFilePathname", "")
            checker = issue.get("checkerName", "")
            in_file = affected_file in file_a or affected_file in file_b
            checker_ok = (not expected) or (checker in expected)
            if in_file and checker_ok:
                issues.append(issue)

        out[version] = {"found": len(issues) > 0, "issue_count": len(issues)}
        found[version] = len(issues) > 0

    if found["V"] is None:
        out["classification"] = "UNKNOWN_NO_JSON_V"
    elif found["S"] is None:
        out["classification"] = "UNKNOWN_NO_JSON_S"
    elif found["V"] and not found["S"]:
        out["classification"] = "TP"
    elif found["V"] and found["S"]:
        out["classification"] = "FP"
    elif not found["V"]:
        out["classification"] = "FN"

    return out


def preflight(coverity_home: Path, build_config: dict) -> list[str]:
    issues: list[str] = []

    if os.name != "nt":
        issues.append("This runner is Windows-only (os.name != 'nt').")

    if not check_tool("git"):
        issues.append("git not found in PATH.")

    for bin_name in ("cov-build", "cov-analyze", "cov-format-errors"):
        p = resolve_cov_bin(coverity_home, bin_name)
        if not p.exists():
            issues.append(f"Coverity binary not found: {p}")

    # Build tooling check is heuristic; per-project commands may override this.
    if not check_tool("cmake"):
        # Keep as warning-style item because not all projects necessarily need cmake.
        issues.append("cmake not found in PATH (required for default raylib/epk2extract commands).")

    for project, cfg in build_config.items():
        cmd = cfg.get("default") if isinstance(cfg, dict) else cfg
        if not cmd:
            issues.append(f"Build command missing for project '{project}'.")

    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows-native Coverity runner for corpus_b")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--project", help="Project id (e.g. raylib, apache_nuttx)")
    group.add_argument("--id", help="Instance id (e.g. RAYLIB-DEFECT-001)")

    parser.add_argument("--version", choices=["V", "S", "both"], default="both")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--classify", action="store_true")
    parser.add_argument("--keep-existing", action="store_true", help="Reuse existing cov_dir if present")
    parser.add_argument("--coverity-home", default=os.environ.get("COVERITY_HOME", DEFAULT_COVERITY_HOME))
    parser.add_argument("--repos-base", default=os.environ.get("REPOS_BASE_WIN", DEFAULT_REPOS_BASE))
    parser.add_argument("--results-base", default=DEFAULT_RESULTS_BASE)
    parser.add_argument("--build-config", default=DEFAULT_BUILD_CONFIG)
    parser.add_argument("--corpus-dir", default=DEFAULT_CORPUS_DIR)
    parser.add_argument("--strict-preflight", action="store_true", help="Fail fast if preflight reports any issue")
    args = parser.parse_args()

    coverity_home = Path(args.coverity_home).resolve()
    repos_base = Path(args.repos_base).resolve()
    results_base = Path(args.results_base).resolve()
    build_config_path = Path(args.build_config).resolve()
    corpus_dir = Path(args.corpus_dir).resolve()

    build_config = load_build_config(build_config_path)

    preflight_issues = preflight(coverity_home, build_config)
    if preflight_issues:
        print("[PREFLIGHT] Issues detected:")
        for i in preflight_issues:
            print(f"  - {i}")
        if args.strict_preflight:
            sys.exit(2)

    instances = load_instances(
        corpus_dir=corpus_dir,
        project_filter=args.project,
        instance_id=args.id,
    )
    if not instances:
        print("No evaluable instances found for the requested filter.")
        sys.exit(1)

    versions = ["V", "S"] if args.version == "both" else [args.version]

    print(f"Processing {len(instances)} instance(s) on Windows Coverity pipeline...")
    outcomes = []

    for inst, project in instances:
        instance_id = inst["id"]
        for version in versions:
            ok_build, msg_build, cov_dir = build_coverity(
                coverity_home=coverity_home,
                repos_base=repos_base,
                results_base=results_base,
                build_config=build_config,
                instance=inst,
                project=project,
                version=version,
                keep_existing=args.keep_existing,
            )
            print(f"[BUILD] {instance_id}/{version}: {msg_build}")

            if not ok_build:
                outcomes.append(
                    {
                        "id": instance_id,
                        "project": project,
                        "version": version,
                        "status": "build_failed",
                        "detail": msg_build,
                        "cov_dir": str(cov_dir) if cov_dir else None,
                    }
                )
                continue

            if args.build_only:
                outcomes.append(
                    {
                        "id": instance_id,
                        "project": project,
                        "version": version,
                        "status": "built_only",
                        "detail": msg_build,
                        "cov_dir": str(cov_dir),
                    }
                )
                continue

            ok_analyze, msg_analyze, json_out = analyze_coverity(
                coverity_home=coverity_home,
                results_base=results_base,
                instance=inst,
                project=project,
                version=version,
            )
            print(f"[ANALYZE] {instance_id}/{version}: {msg_analyze}")

            outcomes.append(
                {
                    "id": instance_id,
                    "project": project,
                    "version": version,
                    "status": "done" if ok_analyze else "analyze_failed",
                    "detail": msg_analyze,
                    "json_out": str(json_out),
                }
            )

    out_log = results_base / "coverity_windows_run_log.json"
    out_log.parent.mkdir(parents=True, exist_ok=True)
    with open(out_log, "w", encoding="utf-8") as f:
        json.dump(outcomes, f, indent=2)
    print(f"Run log written to: {out_log}")

    if args.classify:
        classifications = [classify_instance(inst, project, results_base) for inst, project in instances]
        out_cls = results_base / "coverity_classifications_windows.json"
        with open(out_cls, "w", encoding="utf-8") as f:
            json.dump(classifications, f, indent=2)
        print(f"Classifications written to: {out_cls}")


if __name__ == "__main__":
    main()
