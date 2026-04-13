"""
scripts/fetch_emboss_defects.py
================================
Extrae la lista de defectos confirmados del corpus EMBOSS (Shen et al. ISSTA 2025)
y genera un CSV de candidatos para poblar los ficheros ground_truth.yaml.

Fuentes de datos:
  1. GitHub API — PRs merged con keywords de seguridad
  2. EMBOSS artifact repo — https://github.com/purs3lab/ISSTA-2025-EMBOSS-Artifact
  3. Zenodo artifact — doi.org/10.5281/zenodo.15200316 (SARIFs y spreadsheet)

Uso:
  # Extraer todos los proyectos del top-5
  python scripts/fetch_emboss_defects.py

  # Solo un proyecto
  python scripts/fetch_emboss_defects.py --project apache/nuttx

  # Con token GitHub para evitar rate limits (recomendado)
  GITHUB_TOKEN=ghp_... python scripts/fetch_emboss_defects.py

  # Usar cache local si ya se descargó antes
  python scripts/fetch_emboss_defects.py --use-cache

Output:
  results/emboss_candidates.csv — candidatos para poblar ground_truth.yaml
  results/emboss_candidates_<project>.json — datos completos por proyecto
"""

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime

# ── Configuración ──────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
CACHE_DIR    = Path(".cache/emboss_fetch")
OUTPUT_DIR   = Path("results")

# Top-5 proyectos según Tabla 5 del paper EMBOSS
TOP5_PROJECTS = [
    {"owner": "apache",       "repo": "nuttx",       "corpus_key": "apache_nuttx"},
    {"owner": "contiki-ng",   "repo": "contiki-ng",  "corpus_key": "contiki_ng_emboss"},
    {"owner": "raysan5",      "repo": "raylib",      "corpus_key": "raylib"},
    {"owner": "ARMmbed",      "repo": "mbed-os",     "corpus_key": "mbed_os"},
    {"owner": "openlgtv",     "repo": "epk2extract",  "corpus_key": "epk2extract"},
]

# Queries CodeQL objetivo y sus keywords de búsqueda en PRs
SECURITY_QUERIES = {
    "cpp/inconsistent-null-check":    ["null", "null check", "null pointer", "nullptr", "NULL"],
    "cpp/uncontrolled-allocation-size": ["overflow", "integer overflow", "allocation", "size"],
    "cpp/unbounded-write":            ["buffer", "overflow", "sprintf", "snprintf", "memcpy"],
    "cpp/missing-check-scanf":        ["scanf", "format", "printf", "format string"],
}

# Rate limiting: GitHub API sin auth → 60 req/hora; con auth → 5000 req/hora
REQUEST_DELAY = 1.2 if not GITHUB_TOKEN else 0.1
# ───────────────────────────────────────────────────────────────────────────────


def github_request(url: str, use_cache: bool = False) -> dict | list | None:
    """Realiza una petición a la GitHub API con manejo de rate limits y cache."""
    cache_file = CACHE_DIR / (url.replace("https://", "").replace("/", "_") + ".json")

    if use_cache and cache_file.exists():
        with open(cache_file) as f:
            return json.load(f)

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "sast-benchmark-emboss/1.0",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            time.sleep(REQUEST_DELAY)

            if use_cache:
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                with open(cache_file, "w") as f:
                    json.dump(data, f, indent=2)

            return data

    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"[RATE_LIMIT] GitHub API rate limit alcanzado. "
                  f"Usar GITHUB_TOKEN para aumentar el límite.")
            print(f"  Reset en: {e.headers.get('X-RateLimit-Reset', 'unknown')}")
            return None
        elif e.code == 404:
            print(f"[404] Recurso no encontrado: {url}")
            return None
        else:
            print(f"[HTTP_ERROR] {e.code}: {url}")
            return None
    except Exception as e:
        print(f"[ERROR] {url}: {e}")
        return None


def search_prs(owner: str, repo: str, keywords: list[str],
               use_cache: bool = False) -> list[dict]:
    """Busca PRs merged con keywords de seguridad en un repositorio."""
    found_prs = []
    seen_numbers = set()

    for keyword in keywords:
        # GitHub Search API: PRs merged con keyword en título/body
        query = f"repo:{owner}/{repo}+is:pr+is:merged+{keyword.replace(' ', '+')}"
        url = f"https://api.github.com/search/issues?q={query}&per_page=20&sort=updated"

        data = github_request(url, use_cache)
        if not data:
            continue

        items = data.get("items", [])
        for item in items:
            pr_num = item["number"]
            if pr_num in seen_numbers:
                continue
            seen_numbers.add(pr_num)
            found_prs.append({
                "number":     pr_num,
                "title":      item["title"],
                "html_url":   item["html_url"],
                "merged_at":  item.get("pull_request", {}).get("merged_at"),
                "keyword":    keyword,
            })

    return found_prs


def get_pr_details(owner: str, repo: str, pr_number: int,
                   use_cache: bool = False) -> dict | None:
    """Obtiene detalles completos de un PR incluyendo merge commit y ficheros."""
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    pr_data = github_request(url, use_cache)
    if not pr_data:
        return None

    # Obtener ficheros modificados
    files_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
    files_data = github_request(files_url, use_cache) or []

    merge_sha = pr_data.get("merge_commit_sha")
    parent_sha = None

    # Obtener el SHA del commit padre (commit_vulnerable)
    if merge_sha:
        commit_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{merge_sha}"
        commit_data = github_request(commit_url, use_cache)
        if commit_data:
            parents = commit_data.get("parents", [])
            if parents:
                parent_sha = parents[0].get("sha")

    # Filtrar solo ficheros C/C++
    c_files = [
        f["filename"] for f in files_data
        if f["filename"].endswith((".c", ".cpp", ".h", ".hpp"))
        and not any(
            excl in f["filename"]
            for excl in ["/test", "/tests", "/example", "/doc", "/tools"]
        )
    ]

    return {
        "pr_number":       pr_number,
        "pr_url":          pr_data.get("html_url"),
        "title":           pr_data.get("title"),
        "merged_at":       pr_data.get("merged_at"),
        "merge_commit_sha": merge_sha,
        "parent_sha":      parent_sha,
        "c_files":         c_files,
        "all_files":       [f["filename"] for f in files_data],
        "body_excerpt":    (pr_data.get("body") or "")[:200],
    }


def classify_query(title: str, body: str) -> str:
    """Intenta inferir la query CodeQL más probable del título/body del PR."""
    title_lower = (title + " " + body).lower()

    if any(kw in title_lower for kw in ["null", "nullptr", "null pointer", "null check"]):
        return "cpp/inconsistent-null-check"
    if any(kw in title_lower for kw in ["sprintf", "snprintf", "buffer overflow", "unbounded"]):
        return "cpp/unbounded-write"
    if any(kw in title_lower for kw in ["integer overflow", "int overflow", "allocation size"]):
        return "cpp/uncontrolled-allocation-size"
    if any(kw in title_lower for kw in ["scanf", "format string", "printf"]):
        return "cpp/missing-check-scanf"
    if any(kw in title_lower for kw in ["buffer", "overflow", "overrun", "memcpy", "memset"]):
        return "cpp/unbounded-write"

    return "UNKNOWN"


def classify_cwe(query: str) -> tuple[str, str]:
    """Mapea query CodeQL → (CWE-ID, cwe_family)."""
    mapping = {
        "cpp/inconsistent-null-check":     ("CWE-476", "null-deref"),
        "cpp/unbounded-write":             ("CWE-120", "buffer-overflow"),
        "cpp/uncontrolled-allocation-size": ("CWE-190", "integer-overflow"),
        "cpp/missing-check-scanf":         ("CWE-134", "format-string"),
    }
    return mapping.get(query, ("UNKNOWN", "other"))


def fetch_project(project_info: dict, use_cache: bool = False) -> list[dict]:
    """Extrae candidatos de defectos para un proyecto."""
    owner = project_info["owner"]
    repo  = project_info["repo"]
    key   = project_info["corpus_key"]

    print(f"\n[FETCH] {owner}/{repo} ({key})")
    print(f"  Buscando PRs con keywords de seguridad...")

    # Buscar PRs con todas las keywords
    all_keywords = []
    for keywords in SECURITY_QUERIES.values():
        all_keywords.extend(keywords[:2])  # Max 2 keywords por query para evitar rate limit
    all_keywords = list(dict.fromkeys(all_keywords))  # Deduplicar manteniendo orden

    candidate_prs = search_prs(owner, repo, all_keywords, use_cache)
    print(f"  {len(candidate_prs)} PRs candidatos encontrados")

    # Obtener detalles de cada PR
    candidates = []
    for pr_info in candidate_prs[:30]:  # Limitar a 30 para evitar rate limit
        print(f"  PR #{pr_info['number']}: {pr_info['title'][:60]}")
        details = get_pr_details(owner, repo, pr_info["number"], use_cache)
        if not details:
            continue

        # Solo PRs que modificaron ficheros C/C++
        if not details["c_files"]:
            continue

        query   = classify_query(details["title"], details["body_excerpt"])
        cwe_id, cwe_family = classify_cwe(query)

        candidate = {
            "corpus_key":       key,
            "owner":            owner,
            "repo":             repo,
            "pr_number":        details["pr_number"],
            "pr_url":           details["pr_url"],
            "title":            details["title"],
            "merged_at":        details["merged_at"],
            "merge_commit_sha": details["merge_commit_sha"],
            "parent_sha":       details["parent_sha"],
            "c_files":          details["c_files"],
            "inferred_query":   query,
            "inferred_cwe_id":  cwe_id,
            "inferred_cwe_family": cwe_family,
            "needs_manual_review": query == "UNKNOWN" or not details["parent_sha"],
        }
        candidates.append(candidate)

    print(f"  {len(candidates)} candidatos con ficheros C/C++")
    return candidates


def save_csv(candidates: list[dict], output_path: Path):
    """Guarda los candidatos en un CSV para revisión manual."""
    if not candidates:
        print("[WARN] No hay candidatos para guardar.")
        return

    fieldnames = [
        "corpus_key", "owner", "repo", "pr_number", "pr_url", "title",
        "merged_at", "merge_commit_sha", "parent_sha",
        "primary_c_file", "inferred_query", "inferred_cwe_id",
        "inferred_cwe_family", "needs_manual_review"
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for c in candidates:
            row = {k: c.get(k, "") for k in fieldnames}
            # Tomar el primer fichero C como primario
            row["primary_c_file"] = c.get("c_files", [""])[0] if c.get("c_files") else ""
            writer.writerow(row)

    print(f"\nCSV guardado en: {output_path}")


def save_json(candidates: list[dict], project_key: str):
    """Guarda los candidatos completos en JSON por proyecto."""
    out_path = OUTPUT_DIR / f"emboss_candidates_{project_key}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(candidates, f, indent=2)
    print(f"JSON guardado en: {out_path}")


def check_rate_limit():
    """Muestra el estado del rate limit de la GitHub API."""
    data = github_request("https://api.github.com/rate_limit")
    if data:
        core = data.get("rate", {})
        search = data.get("resources", {}).get("search", {})
        print(f"[RATE_LIMIT] Core: {core.get('remaining')}/{core.get('limit')} "
              f"(reset: {datetime.fromtimestamp(core.get('reset', 0)).strftime('%H:%M')})")
        print(f"[RATE_LIMIT] Search: {search.get('remaining')}/{search.get('limit')} "
              f"(reset: {datetime.fromtimestamp(search.get('reset', 0)).strftime('%H:%M')})")


def generate_yaml_template(candidates: list[dict], project_key: str) -> str:
    """Genera una plantilla YAML para los candidatos del proyecto."""
    lines = [
        f"# Plantilla generada por fetch_emboss_defects.py",
        f"# Proyecto: {project_key}",
        f"# Revisar y completar manualmente antes de usar",
        f"# Fecha: {datetime.now().strftime('%Y-%m-%d')}",
        "",
    ]

    for i, c in enumerate(candidates[:8], 1):  # Max 8 por proyecto
        inst_id = f"{project_key.upper().replace('_', '-')}-DEFECT-{i:03d}"
        primary_file = c.get("c_files", ["UNKNOWN"])[0]

        lines.extend([
            f"  - id: {inst_id}",
            f"    source: shen_et_al_issta_2025",
            f"    confirmed_by: pr_merged",
            f"    pr_url: {c['pr_url']}",
            f"    cwe_id: {c['inferred_cwe_id']}",
            f"    cwe_family: {c['inferred_cwe_family']}",
            f"    codeql_query: {c['inferred_query']}",
            f"    severity: error",
            f"    affected_file: {primary_file}",
            f"    affected_function: REVISAR_MANUALMENTE",
            f"    affected_line_approx: 0",
            f"    commit_fix: {c.get('merge_commit_sha') or 'PENDIENTE'}",
            f"    commit_vulnerable: {c.get('parent_sha') or 'PENDIENTE'}",
            f"    commit_verified: false",
            f"    structural_fn: false",
            f"    needs_manual_verification: {'true' if c['needs_manual_review'] else 'false'}",
            f"    notes: >",
            f"      {c['title'][:100]}",
            f"      PR merged: {c.get('merged_at', 'unknown')[:10]}.",
            f"      Generado automáticamente — verificar localización exacta.",
            "",
        ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Extrae defectos EMBOSS de GitHub para poblar ground_truth.yaml"
    )
    parser.add_argument(
        "--project",
        help="Solo procesar un proyecto (e.g. 'apache/nuttx')"
    )
    parser.add_argument(
        "--use-cache",
        action="store_true",
        help="Usar cache local para evitar peticiones duplicadas"
    )
    parser.add_argument(
        "--check-rate-limit",
        action="store_true",
        help="Solo mostrar el estado del rate limit y salir"
    )
    parser.add_argument(
        "--generate-yaml",
        action="store_true",
        help="Generar plantillas YAML además del CSV"
    )
    parser.add_argument(
        "--output",
        default="results/emboss_candidates.csv",
        help="Ruta del CSV de salida (default: results/emboss_candidates.csv)"
    )
    args = parser.parse_args()

    if not GITHUB_TOKEN:
        print("[WARN] GITHUB_TOKEN no configurado. Rate limit: 10 req/min (búsqueda).")
        print("  Para aumentar: export GITHUB_TOKEN=ghp_...\n")

    if args.check_rate_limit:
        check_rate_limit()
        return

    # Filtrar proyectos si se especifica uno
    projects = TOP5_PROJECTS
    if args.project:
        owner, repo = args.project.split("/")
        projects = [p for p in TOP5_PROJECTS if p["owner"] == owner and p["repo"] == repo]
        if not projects:
            print(f"[ERROR] Proyecto '{args.project}' no está en el top-5 EMBOSS.")
            print(f"  Proyectos disponibles: {[f'{p[\"owner\"]}/{p[\"repo\"]}' for p in TOP5_PROJECTS]}")
            sys.exit(1)

    all_candidates = []
    for project_info in projects:
        candidates = fetch_project(project_info, args.use_cache)
        all_candidates.extend(candidates)

        # Guardar JSON por proyecto
        save_json(candidates, project_info["corpus_key"])

        # Generar plantilla YAML si se pide
        if args.generate_yaml:
            yaml_content = generate_yaml_template(candidates, project_info["corpus_key"])
            yaml_out = OUTPUT_DIR / f"emboss_template_{project_info['corpus_key']}.yaml"
            yaml_out.parent.mkdir(parents=True, exist_ok=True)
            with open(yaml_out, "w") as f:
                f.write(yaml_content)
            print(f"Plantilla YAML guardada en: {yaml_out}")

    # Guardar CSV consolidado
    save_csv(all_candidates, Path(args.output))

    print(f"\nResumen:")
    print(f"  Total candidatos: {len(all_candidates)}")
    by_project = {}
    for c in all_candidates:
        k = c["corpus_key"]
        by_project[k] = by_project.get(k, 0) + 1
    for proj, count in sorted(by_project.items()):
        print(f"  {proj:30s}: {count} candidatos")

    print(f"\nSiguiente paso:")
    print(f"  1. Revisar {args.output} y seleccionar las mejores instancias")
    print(f"  2. Verificar manualmente los campos 'needs_manual_review=true'")
    print(f"  3. Actualizar los ground_truth.yaml en corpus_b/")
    print(f"  4. Ejecutar: python scripts/validate_ground_truth.py --gt corpus_b/*/ground_truth.yaml")


if __name__ == "__main__":
    main()
