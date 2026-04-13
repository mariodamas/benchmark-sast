#!/usr/bin/env python3
"""
scripts/verify_and_fix_commits.py
===================================
Verifica los commit hashes del ground truth contra el repositorio real.
Para cada CVE con commit_verified: false:
  1. Comprueba si el hash existe en el repo (git cat-file -t)
  2. Si existe → marca commit_verified: true
  3. Si no existe → busca en el log por CVE ID, advisory keywords, o PR número
  4. Si encuentra alternativa → actualiza ambos campos y marca commit_verified: true
  5. Si no encuentra nada → reporta como MANUAL_REVIEW_NEEDED

USO:
    python3 scripts/verify_and_fix_commits.py \
        --gt corpus/mbedtls/ground_truth.yaml \
        --repo /tmp/sast-benchmark-repos/mbedtls \
        [--dry-run]   (solo reporta, no modifica el YAML)
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml


def git(repo: str, *args) -> tuple[int, str]:
    result = subprocess.run(
        ["git", "-C", repo] + list(args),
        capture_output=True, text=True
    )
    return result.returncode, result.stdout.strip()


def commit_exists(repo: str, sha: str) -> bool:
    rc, _ = git(repo, "cat-file", "-t", sha)
    return rc == 0


def search_commit_by_cve(repo: str, cve_id: str) -> list[str]:
    """
    Busca commits que mencionan el CVE en el mensaje de commit.
    Devuelve lista de hashes ordenados por fecha (más reciente primero).
    """
    _, out = git(repo, "log", "--all", "--oneline",
                 "--grep", cve_id, "--format=%H %s")
    if not out:
        return []
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return [l.split()[0] for l in lines]


def search_commit_by_file(repo: str, affected_file: str, cve_id: str) -> list[str]:
    """
    Busca commits que tocan el archivo afectado y mencionan palabras clave del CVE.
    """
    year = cve_id.split("-")[1] if "-" in cve_id else ""
    _, out = git(repo, "log", "--all", "--oneline",
                 f"--after={int(year)-1}-01-01" if year else "--all",
                 f"--before={int(year)+2}-12-31" if year else "--all",
                 "--", affected_file,
                 "--format=%H %s")
    if not out:
        return []
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    # Filtrar los que mencionan security/fix/vuln/advisory
    security_keywords = ["fix", "security", "vuln", "advisory", "cve", "patch",
                         "overflow", "null", "deref", "integer", "buffer"]
    results = []
    for line in lines:
        if any(kw in line.lower() for kw in security_keywords):
            results.append(line.split()[0])
    return results[:5]  # máximo 5 candidatos


def get_parent_commit(repo: str, sha: str) -> str:
    """Devuelve el commit padre (la versión vulnerable = commit justo antes del fix)."""
    _, out = git(repo, "rev-parse", f"{sha}^")
    return out.strip() if out else ""


def get_commit_info(repo: str, sha: str) -> str:
    """Devuelve el mensaje del commit."""
    _, out = git(repo, "log", "--format=%s (%ad)", "--date=short", "-1", sha)
    return out.strip()


def verify_and_fix_ground_truth(gt_path: str, repo_path: str, dry_run: bool = False):
    print(f"\n{'='*70}")
    print(f"Verificando: {gt_path}")
    print(f"Repo:        {repo_path}")
    print(f"Modo:        {'DRY-RUN (sin cambios)' if dry_run else 'APLICANDO CAMBIOS'}")
    print(f"{'='*70}\n")

    with open(gt_path) as f:
        gt = yaml.safe_load(f)
        raw_text = f.read() if False else open(gt_path).read()

    project = gt["project"]
    instances = gt["instances"]

    stats = {
        "already_verified": 0,
        "hash_exists_updated": 0,
        "hash_found_in_log": 0,
        "manual_review": 0,
        "structural_fn_skipped": 0,
    }

    # Modificaciones a aplicar: lista de (old_str, new_str)
    changes = []

    for inst in instances:
        cve_id = inst["cve"]
        already_verified = inst.get("commit_verified", False)

        if inst.get("structural_fn"):
            stats["structural_fn_skipped"] += 1
            # También verificamos los commits de FN estructurales
            pass  # no saltamos, los verificamos igualmente

        commit_v = inst.get("commit_vulnerable", "")
        commit_fix = inst.get("commit_fix", "")
        affected_file = inst.get("affected_file", "")

        if already_verified:
            stats["already_verified"] += 1
            print(f"  ✓ {cve_id}: ya verificado")
            continue

        print(f"\n  ── {cve_id} ({inst['cwe_family']}) ──")
        print(f"     Archivo: {affected_file}")
        print(f"     commit_vulnerable: {commit_v}")
        print(f"     commit_fix:        {commit_fix}")

        v_exists = commit_exists(repo_path, commit_v) if commit_v else False
        f_exists = commit_exists(repo_path, commit_fix) if commit_fix else False

        print(f"     commit_v existe:   {'✓' if v_exists else '✗'}")
        print(f"     commit_fix existe: {'✓' if f_exists else '✗'}")

        if v_exists and f_exists:
            # Ambos existen → solo marcar como verificado
            info_v = get_commit_info(repo_path, commit_v)
            info_f = get_commit_info(repo_path, commit_fix)
            print(f"     V info:   {info_v}")
            print(f"     Fix info: {info_f}")
            print(f"     → AMBOS EXISTEN. Marcando commit_verified: true")
            changes.append((
                f"commit_verified: false  # {cve_id}",
                f"commit_verified: true   # {cve_id}",
            ))
            # Cambio sin comentario también
            changes.append((
                f"    commit_verified: false\n",
                f"    commit_verified: true\n",
            ))
            stats["hash_exists_updated"] += 1
            inst["_status"] = "EXISTS"
            inst["_new_commit_v"] = commit_v
            inst["_new_commit_fix"] = commit_fix
            continue

        # Al menos uno no existe → buscar en el log
        print(f"     Buscando en git log por '{cve_id}'...")
        candidates = search_commit_by_cve(repo_path, cve_id)

        if not candidates:
            # Intentar búsqueda por archivo
            print(f"     Ningún commit menciona el CVE. Buscando por archivo...")
            candidates = search_commit_by_file(repo_path, affected_file, cve_id)

        if candidates:
            print(f"     Candidatos encontrados: {len(candidates)}")
            for c in candidates[:3]:
                info = get_commit_info(repo_path, c)
                print(f"       {c[:12]}  {info}")

            # El primer candidato es el fix; su padre es el vulnerable
            new_fix = candidates[0]
            new_v = get_parent_commit(repo_path, new_fix)

            if new_v:
                fix_info = get_commit_info(repo_path, new_fix)
                v_info = get_commit_info(repo_path, new_v)
                print(f"     → FIX encontrado:  {new_fix[:12]} — {fix_info}")
                print(f"     → VULN (padre^1):  {new_v[:12]} — {v_info}")

                inst["_status"] = "FOUND"
                inst["_new_commit_v"] = new_v
                inst["_new_commit_fix"] = new_fix
                stats["hash_found_in_log"] += 1
            else:
                print(f"     → Fix encontrado pero sin padre (commit raíz). MANUAL_REVIEW.")
                inst["_status"] = "MANUAL_REVIEW"
                inst["_reason"] = "fix_found_no_parent"
                stats["manual_review"] += 1
        else:
            print(f"     → No encontrado. MANUAL_REVIEW_NEEDED")
            inst["_status"] = "MANUAL_REVIEW"
            inst["_reason"] = "not_found_in_log"
            stats["manual_review"] += 1

    # -----------------------------------------------------------------------
    # Aplicar cambios al YAML (reescritura conservadora por instancia)
    # -----------------------------------------------------------------------
    print(f"\n{'='*70}")
    print("RESUMEN:")
    print(f"  Ya verificados:       {stats['already_verified']}")
    print(f"  Hash existe → OK:     {stats['hash_exists_updated']}")
    print(f"  Encontrado en log:    {stats['hash_found_in_log']}")
    print(f"  MANUAL_REVIEW:        {stats['manual_review']}")
    print(f"{'='*70}")

    if dry_run:
        print("\n[DRY-RUN] No se han aplicado cambios.")
        # Mostrar qué cambiaría
        for inst in instances:
            if inst.get("_status") in ("EXISTS", "FOUND"):
                print(f"  {inst['cve']}: {inst.get('commit_vulnerable','')} → {inst['_new_commit_v']}")
                print(f"  {inst['cve']}: {inst.get('commit_fix','')} → {inst['_new_commit_fix']}")
        return stats

    # Reescribir el YAML instancia por instancia
    updated_content = raw_text
    for inst in instances:
        status = inst.get("_status")
        if status not in ("EXISTS", "FOUND"):
            continue

        old_v   = inst.get("commit_vulnerable", "")
        old_fix = inst.get("commit_fix", "")
        new_v   = inst["_new_commit_v"]
        new_fix = inst["_new_commit_fix"]

        # Reemplazar commits (solo si cambian)
        if old_v and old_v != new_v:
            updated_content = updated_content.replace(
                f'commit_vulnerable: "{old_v}"',
                f'commit_vulnerable: "{new_v}"'
            )
            updated_content = updated_content.replace(
                f"commit_vulnerable: \"{old_v}\"",
                f"commit_vulnerable: \"{new_v}\""
            )
            # Sin comillas también
            updated_content = updated_content.replace(
                f"commit_vulnerable: {old_v}",
                f"commit_vulnerable: {new_v}"
            )

        if old_fix and old_fix != new_fix:
            updated_content = updated_content.replace(
                f'commit_fix: "{old_fix}"',
                f'commit_fix: "{new_fix}"'
            )
            updated_content = updated_content.replace(
                f"commit_fix:        \"{old_fix}\"",
                f"commit_fix:        \"{new_fix}\""
            )
            updated_content = updated_content.replace(
                f"commit_fix:        {old_fix}",
                f"commit_fix:        {new_fix}"
            )

        # Marcar commit_verified: true (para este CVE específico)
        # Usamos el cve_id como ancla para localizar el bloque correcto
        # Estrategia: reemplazar la primera ocurrencia de "commit_verified: false"
        # que aparece después del CVE ID en el bloque de esta instancia
        cve_marker = f"cve: {inst['cve']}"
        idx = updated_content.find(cve_marker)
        if idx != -1:
            # Buscar "commit_verified: false" después de idx
            after = updated_content[idx:]
            # Encontrar el límite del bloque (próximo "- id:" o fin)
            next_block = re.search(r"\n  - id:", after[1:])
            block_end = idx + 1 + next_block.start() if next_block else len(updated_content)
            block = updated_content[idx:block_end]
            new_block = block.replace("commit_verified: false", "commit_verified: true", 1)
            updated_content = updated_content[:idx] + new_block + updated_content[block_end:]

    with open(gt_path, "w") as f:
        f.write(updated_content)

    print(f"\n✓ {gt_path} actualizado.")

    # Generar reporte de MANUAL_REVIEW
    manual = [i for i in instances if i.get("_status") == "MANUAL_REVIEW"]
    if manual:
        print(f"\n⚠️  {len(manual)} instancias requieren revisión manual:")
        for inst in manual:
            print(f"   {inst['cve']} — {inst.get('_reason', '?')}")
            print(f"     Sugerencia: git -C {repo_path} log --oneline --all -- {inst.get('affected_file','')}")

    return stats


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--gt", required=True, help="Ruta al ground_truth.yaml")
    p.add_argument("--repo", required=True, help="Ruta al repositorio clonado")
    p.add_argument("--dry-run", action="store_true",
                   help="Solo reporta, no modifica el YAML")
    args = p.parse_args()

    if not Path(args.repo).exists():
        print(f"ERROR: Repositorio no encontrado: {args.repo}")
        sys.exit(1)
    if not Path(args.repo / ".git" if False else args.repo).is_dir():
        print(f"ERROR: {args.repo} no parece un repositorio git")
        sys.exit(1)

    stats = verify_and_fix_ground_truth(args.gt, args.repo, args.dry_run)
    sys.exit(0 if stats["manual_review"] == 0 else 2)


if __name__ == "__main__":
    main()
