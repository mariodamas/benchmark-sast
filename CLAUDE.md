# CONTEXTO DEL PROYECTO

Estoy desarrollando un benchmark SAST para mi TFG "Arquitectura DevSecOps 
para Software Embebido C/C++" (Mario Damas, UCLM 2026).

El benchmark actual (mbedTLS, wolfSSL, FreeRTOS, contiki-ng, libcoap) ha 
producido 0 TP con CodeQL. El diagnóstico es que el corpus es homogéneo en 
dominio crypto/RTOS complejo donde las queries estándar de CodeQL no tienen 
cobertura efectiva. (no necesario implementar de nuevo)

Por tanto, pasaremos a utilizar un corpus basado en el paper de Shen et al. ISSTA 2025:
"Finding 709 Defects in 258 Projects: An Experience Report on Applying 
CodeQL to Open-Source Embedded Software"
Artefactos: https://github.com/purs3lab/ISSTA-2025-EMBOSS-Artifact

# OBJETIVO DEL NUEVO CORPUS (corpus_b)

Construir un benchmark con defectos REALES y CONFIRMADOS por desarrolladores,
extraídos del corpus EMBOSS de Shen et al., donde:
- CodeQL tiene probabilidad real de detección (los defectos fueron encontrados 
  por CodeQL en el paper original)
- Podemos ejecutar Coverity sobre los mismos commits para medir complementariedad
- El ground truth está validado externamente (PRs aceptados = confirmación industrial)

La métrica central sigue siendo:
  Marginal_gain = Recall_union - max(Recall_CodeQL, Recall_Coverity)

# ESTRUCTURA A CREAR

Crea la siguiente estructura de directorios y ficheros:
corpus_b/
├── README.md
├── selection_criteria.md
├── apache_nuttx/
│   └── ground_truth.yaml
├── contiki_ng_emboss/
│   └── ground_truth.yaml
├── raylib/
│   └── ground_truth.yaml
├── mbed_os/
│   └── ground_truth.yaml
└── epk2extract/
└── ground_truth.yaml
runner/
└── emboss/
├── run_codeql_emboss.py
├── run_coverity_emboss.py
└── build_scripts/
├── apache_nuttx/
│   └── build.sh
├── contiki_ng_emboss/
│   └── build.sh
├── raylib/
│   └── build.sh
├── mbed_os/
│   └── build.sh
└── epk2extract/
└── build.sh
scripts/
└── fetch_emboss_defects.py
parallel_runner_b.py

# TAREA 1 — Leer los artefactos de Shen et al.

Accede a https://github.com/purs3lab/ISSTA-2025-EMBOSS-Artifact y extrae
la información de defectos confirmados para los 5 proyectos con más defectos
según la Tabla 5 del paper:

1. apache/nuttx         (criticality: 0.69, total: 35, security: 24)
2. contiki-ng/contiki-ng (criticality: 0.67, total: 34, security: 24)
3. raysan5/raylib        (criticality: 0.70, total: 33, security: 33)
4. ARMmbed/mbed-os       (criticality: 0.72, total: 32, security: 22)
5. openlgtv/epk2extract  (criticality: 0.45, total: 29, security: 27)

Para cada proyecto, identifica los defectos confirmados (PRs aceptados)
de tipo SECURITY en estas familias prioritarias:
- cpp/inconsistent-null-check    (CWE-476, 135 instancias en el paper)
- cpp/uncontrolled-allocation-size (CWE-190, 49 instancias)
- cpp/unbounded-write            (CWE-120, 47 instancias)
- cpp/missing-check-scanf        (CWE-134, 70 instancias)

# TAREA 2 — Construir ground_truth.yaml para cada proyecto

Para cada defecto seleccionado necesitas localizar:
- El PR de fix en GitHub que fue aceptado (merged)
- El commit SHA del fix (commit_fix)
- El commit SHA del commit anterior al fix (commit_fix^1 = commit_vulnerable)
- El fichero exacto donde está el defecto
- La línea aproximada del defecto
- La función donde ocurre

Busca en GitHub los PRs de fix para cada proyecto usando:
- github.com/apache/nuttx/pulls (buscar PRs con "null check", "buffer", 
  "allocation" en el título, merged, de los commits citados en el paper)
- github.com/contiki-ng/contiki-ng/pulls (mismos criterios)
- github.com/raysan5/raylib/pulls
- github.com/ARMmbed/mbed-os/pulls  
- github.com/openlgtv/epk2extract/pulls

Para cada defecto encontrado, crea una entrada en ground_truth.yaml 
siguiendo EXACTAMENTE este esquema (que es compatible con el existente 
en corpus/mbedtls/ground_truth.yaml):

```yaml
project: apache_nuttx
repo_url: https://github.com/apache/nuttx
kloc: 800
instances:
  - id: NUTTX-DEFECT-001
    source: shen_et_al_issta_2025
    confirmed_by: pr_merged
    pr_url: https://github.com/apache/nuttx/pull/XXXX
    commit_fix: <SHA completo del commit de fix>
    commit_vulnerable: <SHA del commit anterior = fix^1>
    affected_file: <ruta relativa desde raíz del repo>
    affected_function: <nombre de la función>
    affected_line_approx: <línea aproximada>
    codeql_query: cpp/inconsistent-null-check
    cwe_id: CWE-476
    cwe_family: null-deref
    severity: error
    structural_fn: false
    notes: >
      Defecto confirmado en Shen et al. ISSTA 2025. 
      Developers accepted PR fixing this defect.
```

Selecciona un mínimo de 4 instancias por proyecto y un máximo de 8,
priorizando las que tienen codeql_query con más instancias en el paper
(cpp/inconsistent-null-check primero).

# TAREA 3 — Crear selection_criteria.md

Documenta formalmente los criterios de selección de instancias:

1. Solo defectos con PR merged (confirmación industrial)
2. Solo defectos de tipo security (tag security en la query CodeQL)
3. Familias CWE: null-deref, buffer-overflow, integer-overflow, format-string
4. Fichero afectado debe ser código fuente C/C++ (no tests, no examples)
5. Commit pair debe tener diff claro en el fichero afectado
6. Excluidos: defectos en código de terceros vendoreado dentro del repo

# TAREA 4 — Build scripts

Para cada proyecto, crea un build.sh que:
1. Sea compatible con codeql database create --command=./build.sh
2. Sea compatible con cov-build --dir cov_dir ./build.sh  
3. Compile el máximo de ficheros posible, especialmente los afectados
4. No requiera hardware embebido (compilación en host/native)
5. Incluya comentarios sobre las dependencias necesarias

Para apache/nuttx:
```bash
#!/bin/bash
# Dependencias: kconfig-frontends, genromfs, gcc
# Target: sim (simulator, no hardware required)
cd $REPO_PATH
./tools/configure.sh sim:nsh
make -j$(nproc) 2>&1
```

Para contiki-ng:
```bash
#!/bin/bash
# Dependencias: gcc, make
# Target: native (software simulation)
cd $REPO_PATH
make -C examples/hello-world TARGET=native \
  MODULES="os/net/ipv6 os/net/routing os/net/mac" -j$(nproc) 2>&1
```

Para raylib:
```bash
#!/bin/bash
# Dependencias: libgl1-mesa-dev, libxi-dev, libxcursor-dev
cd $REPO_PATH
mkdir -p build && cd build
cmake .. -DBUILD_SHARED_LIBS=OFF \
         -DCMAKE_BUILD_TYPE=Debug \
         -DPLATFORM=Desktop
make -j$(nproc) 2>&1
```

Adapta los otros dos proyectos con el mismo criterio.

# TAREA 5 — Runner paralelo para corpus_b

Crea parallel_runner_b.py con esta lógica:

```python
"""
Runner paralelo para corpus_b (EMBOSS Shen et al.).
Ejecuta CodeQL Y Coverity sobre los mismos commits V/S.
Diseño de fases:
  Fase A: git checkout + build (I/O bound) → MAX 3 workers
  Fase B: codeql analyze (CPU bound)       → MAX 4 workers  
  Fase C: cov-analyze (CPU bound)          → MAX 2 workers (Coverity es pesado)

Diferencia con corpus original: aquí el build_script es por proyecto,
no por CVE. Todos los CVEs del mismo proyecto comparten build logic.
"""

import subprocess
import concurrent.futures
import yaml
import json
import zipfile
from pathlib import Path
from datetime import datetime

# ── Configuración ──────────────────────────────────
CODEQL_BINARY   = Path("/opt/codeql/codeql")
COVERITY_HOME   = Path("/opt/cov-analysis")
REPOS_BASE      = Path("/tmp/repos_b")
RESULTS_BASE    = Path("results/corpus_b")
BUILD_SCRIPTS   = Path("runner/emboss/build_scripts")

MAX_BUILD_WORKERS    = 3
MAX_CODEQL_WORKERS   = 4
MAX_COVERITY_WORKERS = 2
# ───────────────────────────────────────────────────

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
        print(f"[INVALID_BUILD] {instance_id}: {affected_file} ausente en src.zip")
        if similar:
            print(f"  Ficheros similares encontrados: {similar}")
        return False
    
    print(f"[BUILD_OK] {instance_id}: {affected_file} confirmado en src.zip")
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
    
    result = {
        "instance_id": instance_id,
        "project": project,
        "versions": {}
    }
    
    for version, commit in [
        ("V", instance["commit_vulnerable"]),
        ("S", instance["commit_fix"])
    ]:
        db_path_codeql   = RESULTS_BASE / "codeql"   / project / instance_id / version / "db"
        db_path_coverity = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"
        
        if db_path_codeql.exists() and db_path_coverity.exists():
            print(f"[SKIP_BUILD] {instance_id}/{version}: ya existe")
            result["versions"][version] = "skipped"
            continue
        
        # Checkout
        subprocess.run(
            ["git", "-C", str(repo_path), "checkout", "-f", commit],
            check=True, capture_output=True
        )
        
        # Build CodeQL
        if not db_path_codeql.exists():
            db_path_codeql.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([
                str(CODEQL_BINARY), "database", "create", str(db_path_codeql),
                "--language=cpp",
                f"--command=bash {build_script}",
                "--source-root", str(repo_path),
                "--threads=2",
                "--overwrite"
            ], check=True, env={"REPO_PATH": str(repo_path), **__import__("os").environ})
        
        # Validar build antes de continuar con Coverity
        if not validate_affected_file_in_db(
            db_path_codeql, instance["affected_file"], f"{instance_id}/{version}"
        ):
            result["versions"][version] = "invalid_build"
            continue
        
        # Build Coverity (reutiliza el mismo checkout)
        if not db_path_coverity.exists():
            db_path_coverity.mkdir(parents=True, exist_ok=True)
            subprocess.run([
                str(COVERITY_HOME / "bin" / "cov-build"),
                "--dir", str(db_path_coverity),
                "bash", str(build_script)
            ], check=True, env={"REPO_PATH": str(repo_path), **__import__("os").environ})
        
        result["versions"][version] = "built"
    
    return result


def analyze_codeql(instance: dict, project: str) -> dict:
    """Fase B: análisis CodeQL sobre DBs ya construidas."""
    instance_id = instance["id"]
    query       = instance["codeql_query"]
    
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
        subprocess.run([
            str(CODEQL_BINARY), "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={sarif_out}",
            "--threads=4",
            # Suite extendida + query específica de la instancia
            "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
            query
        ], check=True)
    
    return {"instance_id": instance_id, "tool": "codeql", "status": "done"}


def analyze_coverity(instance: dict, project: str) -> dict:
    """Fase C: análisis Coverity sobre cov_dirs ya construidos."""
    instance_id = instance["id"]
    
    for version in ["V", "S"]:
        cov_dir    = RESULTS_BASE / "coverity" / project / instance_id / version / "cov_dir"
        json_out   = RESULTS_BASE / "coverity" / project / instance_id / f"{version}.json"
        
        if json_out.exists():
            print(f"[SKIP_COVERITY] {instance_id}/{version}: JSON ya existe")
            continue
        
        if not cov_dir.exists():
            print(f"[SKIP_COVERITY] {instance_id}/{version}: cov_dir no disponible")
            continue
        
        # Análisis con checkers específicos para las familias del corpus
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
        
        # Exportar resultados
        json_out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            str(COVERITY_HOME / "bin" / "cov-format-errors"),
            "--dir", str(cov_dir),
            "--json-output-v8", str(json_out)
        ], check=True)
    
    return {"instance_id": instance_id, "tool": "coverity", "status": "done"}


def run_corpus_b(ground_truth_paths: list):
    """Punto de entrada principal."""
    
    all_instances = []
    for gt_path in ground_truth_paths:
        with open(gt_path) as f:
            gt = yaml.safe_load(f)
        project = gt["project"]
        for inst in gt["instances"]:
            if not inst.get("structural_fn", False):
                inst["_project"] = project
                all_instances.append(inst)
    
    print(f"\nCorpus B: {len(all_instances)} instancias evaluables")
    print(f"Proyectos: {set(i['_project'] for i in all_instances)}\n")
    
    # FASE A — Builds paralelos
    print("=== FASE A: Compilación paralela (CodeQL + Coverity) ===")
    build_results = {}
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_BUILD_WORKERS) as ex:
        futures = {
            ex.submit(build_both_tools, inst, inst["_project"], REPOS_BASE): inst["id"]
            for inst in all_instances
        }
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            build_results[r["instance_id"]] = r
            print(f"  ✓ Build: {r['instance_id']}")
    
    # Filtrar instancias con build válido
    valid_instances = [
        inst for inst in all_instances
        if all(
            build_results.get(inst["id"], {}).get("versions", {}).get(v) 
            in ("built", "skipped")
            for v in ["V", "S"]
        )
    ]
    print(f"\n  Instancias con build válido: {len(valid_instances)}/{len(all_instances)}")
    
    if not valid_instances:
        print("[ERROR] Ninguna instancia tiene build válido. Revisar build scripts.")
        return
    
    # FASE B — CodeQL paralelo
    print("\n=== FASE B: Análisis CodeQL paralelo ===")
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=MAX_CODEQL_WORKERS) as ex:
        futures = {
            ex.submit(analyze_codeql, inst, inst["_project"]): inst["id"]
            for inst in valid_instances
        }
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            print(f"  ✓ CodeQL: {r['instance_id']}")
    
    # FASE C — Coverity paralelo
    print("\n=== FASE C: Análisis Coverity paralelo ===")
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=MAX_COVERITY_WORKERS) as ex:
        futures = {
            ex.submit(analyze_coverity, inst, inst["_project"]): inst["id"]
            for inst in valid_instances
        }
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            print(f"  ✓ Coverity: {r['instance_id']}")
    
    print("\n=== Corpus B completado ===")
    print(f"Resultados en: {RESULTS_BASE}")
    print("Siguiente paso: python deduplicator/dedup_findings.py --corpus b")


if __name__ == "__main__":
    gt_paths = list(Path("corpus_b").glob("*/ground_truth.yaml"))
    run_corpus_b(gt_paths)
```

# TAREA 6 — Script de extracción de defectos EMBOSS

Crea scripts/fetch_emboss_defects.py que:

1. Clone o acceda al artefacto de Shen et al.
2. Parsee la lista de defectos confirmados (PRs aceptados)
3. Para cada proyecto del top-5, extraiga:
   - URL del PR
   - Commit de fix (merge commit SHA)
   - Ficheros modificados en ese PR
   - Tipo de defecto (query CodeQL que lo detectó)
4. Genere un CSV de candidatos para poblar los ground_truth.yaml

El script debe usar la GitHub API (sin autenticación para repos públicos)
o parsear los datos del artefacto Zenodo si están disponibles.

Endpoint útil para cada PR:
https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}
https://api.github.com/repos/{owner}/{repo}/commits/{sha}

# TAREA 7 — Actualizar CLAUDE.md

Añade al final del CLAUDE.md existente:

```markdown
## Corpus B (EMBOSS Shen et al. ISSTA 2025)

### Propósito
Contraste al corpus crypto (A). Defectos reales confirmados industrialmente
donde CodeQL tiene probabilidad de detección > 0.

### Fuente del ground truth
Shen et al. "Finding 709 Defects in 258 Projects" ISSTA 2025
Artefactos: https://github.com/purs3lab/ISSTA-2025-EMBOSS-Artifact

### Proyectos incluidos
- apache/nuttx       (35 defectos totales en el paper, 24 security)
- contiki-ng         (34 defectos, 24 security)  
- raysan5/raylib     (33 defectos, todos security)
- ARMmbed/mbed-os    (32 defectos, 22 security)
- openlgtv/epk2extract (29 defectos, 27 security)

### CWEs objetivo
- CWE-476 (null-deref)    → query: cpp/inconsistent-null-check
- CWE-120 (buffer-overflow) → query: cpp/unbounded-write  
- CWE-190 (int-overflow)  → query: cpp/uncontrolled-allocation-size
- CWE-134 (format-string) → query: cpp/missing-check-scanf

### Validación de build (OBLIGATORIA antes de análisis)
Siempre ejecutar validate_affected_file_in_db() antes de classify.
Un fichero ausente en src.zip = INVALID, no FN.

### Runner
parallel_runner_b.py — fases A(build), B(codeql), C(coverity)
```

# TAREA 8 — Validación final

Después de crear toda la estructura, ejecuta:

```bash
# 1. Validar esquema de todos los ground truth nuevos
python scripts/validate_ground_truth.py \
  --gt corpus_b/apache_nuttx/ground_truth.yaml \
  --gt corpus_b/contiki_ng_emboss/ground_truth.yaml \
  --gt corpus_b/raylib/ground_truth.yaml \
  --gt corpus_b/mbed_os/ground_truth.yaml \
  --gt corpus_b/epk2extract/ground_truth.yaml

# 2. Mostrar resumen del corpus B
python -c "
import yaml
from pathlib import Path
total = 0
for gt in Path('corpus_b').glob('*/ground_truth.yaml'):
    data = yaml.safe_load(gt.read_text())
    n = len([i for i in data['instances'] if not i.get('structural_fn')])
    print(f'{data[\"project\"]}: {n} instancias evaluables')
    total += n
print(f'TOTAL: {total} instancias')
"

# 3. Verificar que los build scripts son ejecutables
find runner/emboss/build_scripts -name "*.sh" -exec chmod +x {} \;
ls -la runner/emboss/build_scripts/*/build.sh
```

# ORDEN DE EJECUCIÓN DE TAREAS

Ejecuta las tareas en este orden estricto:
1 → 2 → 3 → 4 → 5 → 6 → 7 → 8

No pases a la siguiente tarea hasta que la anterior esté completa y 
sin errores. Si en la Tarea 2 no encuentras el PR concreto para alguna
instancia, márcala como `needs_manual_verification: true` en el YAML
y continúa con las siguientes.

# RESTRICCIONES

- NO modifiques nada en corpus/ (corpus original, solo lectura)
- NO modifiques metrics/compute_metrics.py (debe funcionar igual para corpus_b)
- El esquema YAML de ground_truth debe ser 100% compatible con el existente
- Todos los paths en los runners deben ser relativos o usar variables de entorno
- NO hardcodees rutas absolutas salvo CODEQL_BINARY y COVERITY_HOME

## Corpus B (EMBOSS Shen et al. ISSTA 2025)

### Propósito
Contraste al corpus crypto (A). Defectos reales confirmados industrialmente
donde CodeQL tiene probabilidad de detección > 0.

### Fuente del ground truth
Shen et al. "Finding 709 Defects in 258 Projects" ISSTA 2025
Artefactos: https://github.com/purs3lab/ISSTA-2025-EMBOSS-Artifact
Zenodo: doi.org/10.5281/zenodo.15200316

### Proyectos incluidos
- apache/nuttx       (35 defectos totales en el paper, 24 security)
- contiki-ng         (34 defectos, 24 security)
- raysan5/raylib     (33 defectos, todos security)
- ARMmbed/mbed-os    (32 defectos, 22 security)
- openlgtv/epk2extract (29 defectos, 27 security)

### CWEs objetivo
- CWE-476 (null-deref)      → query: cpp/inconsistent-null-check
- CWE-120 (buffer-overflow) → query: cpp/unbounded-write
- CWE-190 (int-overflow)    → query: cpp/uncontrolled-allocation-size
- CWE-134 (format-string)   → query: cpp/missing-check-scanf

### Esquema YAML (Corpus B)
El ground_truth.yaml de corpus_b usa esquema B (sin CVE/CVSS):
  - source: shen_et_al_issta_2025
  - confirmed_by: pr_merged
  - cwe_id: CWE-476 (en lugar de cwe:)
  - codeql_query: cpp/inconsistent-null-check
  - needs_manual_verification: true/false
El validador (scripts/validate_ground_truth.py) detecta el esquema
automáticamente por la presencia del campo 'source'.

### Entradas con verificación pendiente
8 instancias tienen needs_manual_verification: true (commit_vulnerable: null).
Para completarlas:
  git -C /tmp/repos_b/<project> log --format="%H %P" <commit_fix> | awk '{print $2}'
Ver corpus_b/README.md para la lista completa.

### Validación de build (OBLIGATORIA antes de análisis)
Siempre ejecutar validate_affected_file_in_db() antes de classify.
Un fichero ausente en src.zip = INVALID_BUILD, no FN.

### Runner
parallel_runner_b.py — fases A(build), B(codeql), C(coverity)
Opciones: --project, --skip-coverity, --phase A|B|C
