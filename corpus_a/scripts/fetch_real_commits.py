#!/usr/bin/env python3
"""
scripts/fetch_real_commits.py
==============================
Obtiene los commit hashes REALES de mbedTLS y wolfSSL para cada CVE
consultando la GitHub API y las páginas de advisories.

Para cada CVE:
  1. Si tiene fix_pr → GitHub API: GET /repos/.../pulls/{N} → merge_commit_sha
  2. Si tiene fix_advisory → fetch página → extrae commit/PR reference
  3. git fetch del commit específico al repo local
  4. Obtiene el padre (commit_vulnerable = commit antes del fix)
  5. Actualiza el ground_truth.yaml

USO:
    python3 scripts/fetch_real_commits.py \
        --gt corpus/mbedtls/ground_truth.yaml \
        --repo /tmp/sast-benchmark-repos/mbedtls \
        [--token GITHUB_TOKEN]  # opcional pero recomendado (60 req/h sin token)
"""

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import yaml

GITHUB_API = "https://api.github.com"


def api_get(url: str, token: str = None) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "sast-benchmark/1.0")
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  API error {e.code}: {url}")
        return {}
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return {}


def fetch_page(url: str) -> str:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "sast-benchmark/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return ""


def git(repo: str, *args) -> tuple[int, str]:
    result = subprocess.run(
        ["git", "-C", repo] + list(args),
        capture_output=True, text=True
    )
    return result.returncode, result.stdout.strip()


def commit_exists(repo: str, sha: str) -> bool:
    rc, _ = git(repo, "cat-file", "-t", sha)
    return rc == 0


def git_fetch_commit(repo: str, remote_url: str, sha: str) -> bool:
    """Fetch un commit específico en el repo local."""
    if commit_exists(repo, sha):
        return True
    print(f"    Fetching {sha[:12]}...")
    rc, out = git(repo, "fetch", "--depth=2", "origin", sha)
    if rc != 0:
        # Intentar con git fetch sin depth
        rc, out = git(repo, "fetch", "origin", sha)
    return rc == 0 and commit_exists(repo, sha)


def get_parent(repo: str, sha: str) -> str:
    """Devuelve el commit padre (versión vulnerable = estado antes del fix)."""
    rc, out = git(repo, "rev-parse", f"{sha}^")
    if rc == 0 and out and len(out) == 40:
        return out
    return ""


def get_commit_msg(repo: str, sha: str) -> str:
    _, out = git(repo, "log", "--format=%s", "-1", sha)
    return out.strip()[:80]


def extract_pr_number(url: str) -> int:
    """Extrae el número de PR de una URL de GitHub."""
    m = re.search(r"/pull/(\d+)", url)
    return int(m.group(1)) if m else 0


def extract_sha_from_advisory(content: str) -> list[str]:
    """Extrae hashes SHA-1 de una página de advisory."""
    # Buscar hashes de 40 chars hex en el contenido
    hashes = re.findall(r"\b([0-9a-f]{40})\b", content, re.IGNORECASE)
    # Filtrar hashes obviamente placeholders
    real = [h for h in hashes if len(set(h)) > 3]  # más de 3 chars distintos
    return list(dict.fromkeys(real))  # dedup preservando orden


def get_fix_from_pr(repo_owner: str, repo_name: str, pr_num: int,
                    token: str = None) -> str:
    """Obtiene el merge_commit_sha de un PR de GitHub."""
    url = f"{GITHUB_API}/repos/{repo_owner}/{repo_name}/pulls/{pr_num}"
    data = api_get(url, token)
    if not data:
        return ""
    merge_sha = data.get("merge_commit_sha", "")
    state = data.get("state", "?")
    title = data.get("title", "")[:60]
    print(f"    PR #{pr_num} [{state}]: {title}")
    print(f"    merge_commit_sha: {merge_sha[:12] if merge_sha else 'None'}")
    return merge_sha


def get_fix_from_advisory(advisory_url: str, token: str = None) -> str:
    """Intenta obtener el commit de fix desde una página de advisory."""
    content = fetch_page(advisory_url)
    if not content:
        return ""
    hashes = extract_sha_from_advisory(content)
    # Buscar también referencias a PRs de GitHub
    pr_refs = re.findall(r"github\.com/[^/]+/[^/]+/(?:pull|commit)/([0-9a-f]{40}|\d+)", content)
    print(f"    Advisory: {len(hashes)} SHA refs, {len(pr_refs)} PR/commit refs")
    # Devolver el primer hash que no sea claramente de ejemplo
    for h in hashes:
        if not re.match(r"^(0+|f+|1+|abcd|1234)", h, re.I):
            return h
    return ""


# ---------------------------------------------------------------------------
# Mapa CVE → fuente
# ---------------------------------------------------------------------------

MBED_SOURCES = {
    # CVE: (tipo, valor)
    "CVE-2020-36475": ("pr", "Mbed-TLS/mbedtls", 4650),
    "CVE-2020-36480": ("pr", "Mbed-TLS/mbedtls", 4650),   # mismo PR
    "CVE-2020-36476": ("pr", "Mbed-TLS/mbedtls", 4650),   # mismo PR
    "CVE-2020-36478": ("pr", "Mbed-TLS/mbedtls", 4650),   # mismo PR
    "CVE-2020-36479": ("pr", "Mbed-TLS/mbedtls", 4650),   # mismo PR
    "CVE-2021-44732": ("advisory", "https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2021-12/"),
    "CVE-2022-35409": ("advisory", "https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2022-07/"),
    "CVE-2022-46392": ("pr", "Mbed-TLS/mbedtls", 6619),
    "CVE-2022-46393": ("pr", "Mbed-TLS/mbedtls", 6618),
    "CVE-2017-18187": ("advisory", "https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2017-02"),
    "CVE-2018-19608": ("pr", "Mbed-TLS/mbedtls", 2116),
    "CVE-2020-36421": ("pr", "Mbed-TLS/mbedtls", 4655),
    "CVE-2021-43614": ("pr", "Mbed-TLS/mbedtls", 5062),
    "CVE-2024-28755": ("pr", "Mbed-TLS/mbedtls", 8760),
    "CVE-2021-43666": ("pr", "Mbed-TLS/mbedtls", 4465),
    "CVE-2023-52353": ("pr", "Mbed-TLS/mbedtls", 8656),
    "CVE-2018-0498":  ("advisory", "https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2018-02"),
    "CVE-2021-36647": ("pr", "Mbed-TLS/mbedtls", 4838),
    "CVE-2023-43615": ("pr", "Mbed-TLS/mbedtls", 7628),
    "CVE-2020-16150": ("pr", "Mbed-TLS/mbedtls", 3694),
    "CVE-2021-24119": ("pr", "Mbed-TLS/mbedtls", 4412),
    "CVE-2019-16910": ("advisory", "https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2019-10"),
    "CVE-2020-10932": ("advisory", "https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2020-04"),
    "CVE-2024-23170": ("pr", "Mbed-TLS/mbedtls", 8796),
}

WOLFSSL_SOURCES = {
    # wolfSSL no tiene PRs numerados fácilmente en el advisory
    # Usamos búsqueda en el repositorio por CVE ID / tag / fecha
    "CVE-2022-34293": ("search", "wolfSSL/wolfssl", "CVE-2022-34293"),
    "CVE-2023-3724":  ("search", "wolfSSL/wolfssl", "CVE-2023-3724"),
    "CVE-2021-38597": ("search", "wolfSSL/wolfssl", "CVE-2021-38597"),
    "CVE-2022-42905": ("search", "wolfSSL/wolfssl", "CVE-2022-42905"),
    "CVE-2021-3336":  ("search", "wolfSSL/wolfssl", "CVE-2021-3336"),
    "CVE-2022-42771": ("search", "wolfSSL/wolfssl", "CVE-2022-42771"),
    "CVE-2023-6935":  ("search", "wolfSSL/wolfssl", "CVE-2023-6935"),
    "CVE-2023-6936":  ("search", "wolfSSL/wolfssl", "CVE-2023-6936"),
    "CVE-2022-25640": ("search", "wolfSSL/wolfssl", "CVE-2022-25640"),
    "CVE-2023-3122":  ("search", "wolfSSL/wolfssl", "CVE-2023-3122"),
    "CVE-2023-6937":  ("search", "wolfSSL/wolfssl", "CVE-2023-6937"),
    "CVE-2019-14317": ("search", "wolfSSL/wolfssl", "CVE-2019-14317"),
    "CVE-2020-12457": ("search", "wolfSSL/wolfssl", "CVE-2020-12457"),
}


def search_github_commits(repo_full: str, query: str, token: str = None) -> list[str]:
    """Usa la GitHub search API para encontrar commits con el CVE ID."""
    url = f"{GITHUB_API}/search/commits?q={query}+repo:{repo_full}&sort=committer-date"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.cloak-preview+json")
    req.add_header("User-Agent", "sast-benchmark/1.0")
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        items = data.get("items", [])
        return [item["sha"] for item in items[:5]]
    except Exception as e:
        print(f"  Search error: {e}")
        return []


def get_fix_for_cve(cve_id: str, sources: dict, token: str = None) -> str:
    source = sources.get(cve_id)
    if not source:
        print(f"  No hay fuente definida para {cve_id}")
        return ""

    stype = source[0]

    if stype == "pr":
        _, repo_full, pr_num = source
        owner, name = repo_full.split("/")
        return get_fix_from_pr(owner, name, pr_num, token)

    elif stype == "advisory":
        _, advisory_url = source
        sha = get_fix_from_advisory(advisory_url, token)
        if not sha:
            # Intentar buscar por CVE en GitHub commits search
            if "mbedtls" in advisory_url.lower() or "mbed-tls" in advisory_url.lower():
                repo = "Mbed-TLS/mbedtls"
            else:
                return ""
            print(f"    Advisory sin SHA directo. Buscando en GitHub commits...")
            shas = search_github_commits(repo, cve_id, token)
            return shas[0] if shas else ""
        return sha

    elif stype == "search":
        _, repo_full, query = source
        print(f"    Buscando '{query}' en {repo_full}...")
        shas = search_github_commits(repo_full, query, token)
        if shas:
            print(f"    Encontrado: {shas[0][:12]}")
        return shas[0] if shas else ""

    return ""


def update_yaml_instance(yaml_content: str, cve_id: str,
                          new_commit_v: str, new_commit_fix: str) -> str:
    """
    Actualiza en el contenido YAML los campos de commits para el CVE dado.
    Estrategia: encontrar el bloque del CVE y reemplazar los valores.
    """
    # Localizar el bloque de esta instancia por CVE
    pattern = re.compile(
        r"(    cve: " + re.escape(cve_id) + r".*?)(    commit_verified:.*?\n)",
        re.DOTALL
    )

    # Reemplazar commit_vulnerable, commit_fix y commit_verified
    def replace_block(m):
        block = m.group(0)
        # Reemplazar commit_vulnerable
        block = re.sub(
            r"(    commit_vulnerable:\s+)\S+",
            r"\g<1>" + new_commit_v,
            block
        )
        # Reemplazar commit_fix
        block = re.sub(
            r"(    commit_fix:\s+)\S+",
            r"\g<1>" + new_commit_fix,
            block
        )
        # Marcar como verificado
        block = re.sub(
            r"(    commit_verified:\s+)false",
            r"\g<1>true",
            block
        )
        return block

    # Buscar y reemplazar bloque por bloques - más seguro hacerlo línea a línea
    lines = yaml_content.split("\n")
    in_cve_block = False
    cve_found = False
    result_lines = []

    for line in lines:
        if f"cve: {cve_id}" in line and not cve_found:
            in_cve_block = True
            cve_found = True
            result_lines.append(line)
            continue

        if in_cve_block:
            if line.strip().startswith("commit_vulnerable:"):
                indent = len(line) - len(line.lstrip())
                result_lines.append(" " * indent + f"commit_vulnerable: {new_commit_v}")
                continue
            elif line.strip().startswith("commit_fix:"):
                indent = len(line) - len(line.lstrip())
                # Preservar espaciado del YAML (puede tener padding)
                key_part = re.match(r"(\s+commit_fix:\s+)", line)
                if key_part:
                    result_lines.append(key_part.group(1) + new_commit_fix)
                else:
                    result_lines.append(" " * indent + f"commit_fix:        {new_commit_fix}")
                continue
            elif line.strip().startswith("commit_verified:"):
                indent = len(line) - len(line.lstrip())
                result_lines.append(" " * indent + "commit_verified: true")
                in_cve_block = False  # ya terminamos con este bloque
                continue
            # Si encontramos otro CVE, salir del bloque
            elif line.strip().startswith("- id:") and cve_found:
                in_cve_block = False

        result_lines.append(line)

    return "\n".join(result_lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--gt", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--token", default=None, help="GitHub personal access token")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    with open(args.gt) as f:
        gt = yaml.safe_load(f)
        content = open(args.gt).read()

    project = gt["project"]
    print(f"\n{'='*70}")
    print(f"Buscando commits reales para: {project}")
    print(f"{'='*70}")

    sources = MBED_SOURCES if "mbedtls" in project.lower() else WOLFSSL_SOURCES

    stats = {"ok": 0, "failed": 0, "skipped": 0}
    results = {}

    # Cache de PR → merge_commit para PRs compartidos (ej: PR #4650 → 5 CVEs)
    pr_cache = {}

    for inst in gt["instances"]:
        cve_id = inst["cve"]
        if inst.get("commit_verified"):
            print(f"\n  ✓ {cve_id}: ya verificado — skip")
            stats["skipped"] += 1
            continue

        print(f"\n  ── {cve_id} ──")
        source = sources.get(cve_id)

        # Usar cache para PRs compartidos
        cache_key = str(source) if source else cve_id
        if cache_key in pr_cache:
            fix_sha = pr_cache[cache_key]
            print(f"    (cache) fix: {fix_sha[:12]}")
        else:
            fix_sha = get_fix_for_cve(cve_id, sources, args.token)
            if fix_sha:
                pr_cache[cache_key] = fix_sha
            time.sleep(0.5)  # respetar rate limit

        if not fix_sha or len(fix_sha) != 40:
            print(f"    ✗ No se encontró commit fix")
            stats["failed"] += 1
            results[cve_id] = {"status": "FAILED", "reason": "no_fix_found"}
            continue

        # Traer el commit al repo local
        ok = git_fetch_commit(args.repo, None, fix_sha)
        if not ok:
            print(f"    ✗ No se pudo hacer fetch de {fix_sha[:12]}")
            # Intentar con git fetch --unshallow si es shallow
            git(args.repo, "fetch", "--unshallow")
            ok = commit_exists(args.repo, fix_sha)

        if not ok:
            print(f"    ✗ Commit {fix_sha[:12]} no disponible en el repo local")
            stats["failed"] += 1
            results[cve_id] = {"status": "FAILED", "reason": "fetch_failed", "fix": fix_sha}
            continue

        # Obtener padre (versión vulnerable)
        parent_sha = get_parent(args.repo, fix_sha)
        if not parent_sha:
            print(f"    ✗ No se pudo obtener el commit padre")
            stats["failed"] += 1
            results[cve_id] = {"status": "FAILED", "reason": "no_parent", "fix": fix_sha}
            continue

        fix_msg = get_commit_msg(args.repo, fix_sha)
        parent_msg = get_commit_msg(args.repo, parent_sha)
        print(f"    fix (S):  {fix_sha[:12]} — {fix_msg}")
        print(f"    vuln (V): {parent_sha[:12]} — {parent_msg}")

        results[cve_id] = {
            "status": "OK",
            "commit_vulnerable": parent_sha,
            "commit_fix": fix_sha,
        }
        stats["ok"] += 1

    print(f"\n{'='*70}")
    print(f"RESUMEN: OK={stats['ok']} FAILED={stats['failed']} SKIPPED={stats['skipped']}")
    print(f"{'='*70}")

    if args.dry_run:
        print("\n[DRY-RUN] Cambios que se aplicarían:")
        for cve_id, r in results.items():
            if r["status"] == "OK":
                print(f"  {cve_id}: V={r['commit_vulnerable'][:12]} FIX={r['commit_fix'][:12]}")
        return

    # Aplicar cambios al YAML
    updated = content
    for cve_id, r in results.items():
        if r["status"] == "OK":
            updated = update_yaml_instance(
                updated, cve_id,
                r["commit_vulnerable"],
                r["commit_fix"]
            )

    with open(args.gt, "w") as f:
        f.write(updated)
    print(f"\n✓ {args.gt} actualizado con {stats['ok']} commits verificados.")

    # Guardar reporte de fallos
    failed = {k: v for k, v in results.items() if v["status"] == "FAILED"}
    if failed:
        report_path = Path(args.gt).parent / "commit_verification_failures.json"
        with open(report_path, "w") as f:
            json.dump(failed, f, indent=2)
        print(f"\n⚠️  {len(failed)} CVEs sin resolver → {report_path}")
        print("   Estos necesitan verificación manual con las fuentes originales.")


if __name__ == "__main__":
    main()
