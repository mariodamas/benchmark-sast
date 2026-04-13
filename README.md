# SAST Benchmark — CodeQL vs Coverity vs Unión
## TFG: Arquitectura DevSecOps para Software Embebido C/C++
### Mario Damas Sánchez — UCLM 2026

---

## Estructura del repositorio

```
sast-benchmark/
│
├── corpus/                         # Ground truth por proyecto
│   ├── mbedtls/
│   │   └── ground_truth.yaml       # 7 instancias CVE (5 evaluables, 2 FN estructurales)
│   └── wolfssl/
│       └── ground_truth.yaml       # 3 instancias CVE (3 evaluables)
│
├── runner/                         # Ejecutores de herramientas
│   ├── codeql/
│   │   └── run_codeql.py           # Checkout V/S → DB → Analyze → SARIF
│   └── coverity/
│       └── run_coverity.py         # Checkout V/S → cov-build → cov-analyze → JSON v8
│
├── deduplicator/
│   └── dedup_findings.py           # Motor de deduplicación con clave canónica
│
├── metrics/
│   └── compute_metrics.py          # Plano 1 (instance) + Plano 2 (finding)
│
├── scripts/
│   ├── validate_ground_truth.py    # Validación de esquema y coherencia del GT
│   └── cross_project_analysis.py  # Consistencia cross-project mbedTLS ↔ wolfSSL
│
├── pipeline/
│   └── .github/workflows/
│       └── sast_benchmark.yml      # CI completo (Jobs paralelos por herramienta)
│
├── config/
│   └── coverity_checkers.conf      # Checkers específicos para las CWE del GT
│
└── results/                        # Generado — no versionar en git
    ├── raw/
    │   ├── codeql/{project}/{CVE}/{V|S}.sarif
    │   └── coverity/{project}/{CVE}/{V|S}.json
    ├── deduplicated/{project}/{CVE}_dedup.json
    └── metrics/{project}/
        ├── instance_level_metrics.json
        ├── finding_level_metrics.json
        └── benchmark_summary.json
```

---

## Diseño metodológico

### Unidad de análisis: la instancia (no la alerta)

La unidad de análisis principal es el **CVE**, no el finding.
Cada CVE del corpus es una instancia del benchmark con dos versiones:
- `V` (commit_vulnerable): el commit anterior al parche (`fix~1`)
- `S` (commit_fix): el commit de parche

**Clasificación de alertas:**

| Alerta en V | Alerta en S | Clasificación |
|:-----------:|:-----------:|:-------------:|
| ✓ | ✗ | **TP** — detecta la vulnerabilidad |
| ✓ | ✓ | **FP** — persiste tras el fix (ruido) |
| ✗ | — | **FN** — no detecta la vulnerabilidad |

### Métricas de instancia (Plano 1 — métrica principal)

```
Recall_CodeQL   = TP_CodeQL   / N_evaluable
Recall_Coverity = TP_Coverity / N_evaluable
Recall_union    = TP_union    / N_evaluable

donde:
  TP_union  = TP_overlap + TP_unique_CodeQL + TP_unique_Coverity
  N_evaluable = total instancias - FN_estructurales
```

**Métrica central del benchmark:**
```
Marginal_gain = Recall_union - max(Recall_CodeQL, Recall_Coverity)
```
Responde exactamente a: *"¿meter Coverity sobre CodeQL aporta cobertura real o solo coste?"*

### Métricas de finding (Plano 2 — secundario)

```
FP_per_KLOC = total_FP_deduplicados / KLOC_proyecto
FP_per_CVE  = total_FP_deduplicados / N_evaluable
Revision_cost_hours = total_findings_deduplicados × 15min / 60
```

### Clave de deduplicación

```python
DeduplicationKey = (
    project,
    cve_id,
    version,           # "V" o "S"
    file_path,         # normalizado (relativo, sin prefijos absolutos)
    cwe_family,        # buffer-overflow | integer-overflow | null-deref | use-after-free | ...
    line_bucket,       # line // (2 × LINE_WINDOW)  [LINE_WINDOW = 10 por defecto]
)
```

La ventana de ±10 líneas absorbe diferencias de numeración entre herramientas
(CodeQL reporta en el punto de llamada; Coverity puede reportar en la definición).

### FN estructurales (límite de SAST, no fallos de herramienta)

Los CVEs de tipo timing side-channel (CWE-208, CWE-203) se marcan como
`structural_fn: true` y se **excluyen del denominador** de recall.
Están incluidos deliberadamente en el ground truth para:
1. Documentar el límite técnico de SAST (no detecta side-channels temporales)
2. Alinear con la referencia del Estado del Arte (SC-01 del checklist)
3. Demostrar que el evaluador no los penaliza inadvertidamente

### Fase de validación externa (wolfSSL)

wolfSSL sirve para responder: *"¿Las diferencias entre herramientas son propiedades de las herramientas o del código de mbedTLS?"*

Si `sign(Recall_CodeQL - Recall_Coverity)` es el mismo en mbedTLS y wolfSSL:
→ La conclusión sobre complementariedad es **robusta al corpus**.

Si invierte signo:
→ La complementariedad puede depender del código específico, no de la herramienta.

---

## Ejecución

### Requisitos

```bash
pip install pyyaml         # parsing del ground truth
# CodeQL: https://github.com/github/codeql-action/releases
# Coverity: licencia corporativa (Cipherbit ya dispone de ella)
```

### Fase 1: Validar ground truth

```bash
python scripts/validate_ground_truth.py \
    --gt corpus/mbedtls/ground_truth.yaml \
    --gt corpus/wolfssl/ground_truth.yaml
```

### Fase 2: Ejecutar herramientas

```bash
# CodeQL sobre mbedTLS
python runner/codeql/run_codeql.py \
    --ground-truth corpus/mbedtls/ground_truth.yaml \
    --repo-path /tmp/repos/mbedtls \
    --output-dir results/raw/codeql/mbedtls \
    --codeql-binary /opt/codeql/codeql \
    --threads 4

# Coverity sobre mbedTLS
python runner/coverity/run_coverity.py \
    --ground-truth corpus/mbedtls/ground_truth.yaml \
    --repo-path /tmp/repos/mbedtls \
    --output-dir results/raw/coverity/mbedtls \
    --coverity-home /opt/cov-analysis \
    --threads 4
```

### Fase 3: Deduplicación

```bash
python deduplicator/dedup_findings.py \
    --ground-truth corpus/mbedtls/ground_truth.yaml \
    --codeql-results results/raw/codeql/mbedtls \
    --coverity-results results/raw/coverity/mbedtls \
    --output-dir results/deduplicated/mbedtls \
    --line-window 10
```

### Fase 4: Métricas

```bash
python metrics/compute_metrics.py \
    --dedup-dir results/deduplicated/mbedtls \
    --output-dir results/metrics/mbedtls \
    --kloc 60 \
    --phase primary
```

### Fase 5: Análisis cross-project

```bash
python scripts/cross_project_analysis.py \
    --primary-metrics results/metrics/mbedtls/instance_level_metrics.json \
    --validation-metrics results/metrics/wolfssl/instance_level_metrics.json \
    --output results/metrics/cross_project_consistency.json
```

---

## Aislamiento respecto al pipeline (POC-01 ≠ CAP-02)

Este benchmark es **exclusivamente POC-01 (PoC de SAST)**.
No incluye gates de calidad, normalización con otras familias de herramientas
ni decisiones de dashboard. Eso corresponde a CAP-02 (integración SAST en pipeline),
que depende de las conclusiones de este benchmark.

La secuencia correcta es:
```
POC-01 (este repositorio) → decisión técnica → CAP-02 (integración CI/CD)
```

---

## Advertencia estadística

Con N_evaluable ≤ 10 instancias por corpus, los intervalos de confianza de Wilson
son amplios. Las conclusiones son **indicativas**, no estadísticamente definitivas.
Esto debe documentarse explícitamente en el TFG como limitación metodológica y
como línea de trabajo futuro (ampliar el corpus).
