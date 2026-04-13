# Corpus B — EMBOSS (Shen et al. ISSTA 2025)

## Propósito

Corpus complementario al Corpus A (mbedTLS, wolfSSL) donde CodeQL obtuvo 0 TP
por homogeneidad del dominio crypto. El Corpus B proporciona **contraste medible**:
defectos reales donde CodeQL tiene probabilidad de detección > 0, confirmados
industrialmente mediante PRs aceptados en proyectos open-source activos.

La métrica central sigue siendo:

```
Marginal_gain = Recall_union - max(Recall_CodeQL, Recall_Coverity)
```

## Fuente del Ground Truth

**Paper:** Shen et al. "Finding 709 Defects in 258 Projects: An Experience Report
on Applying CodeQL to Open-Source Embedded Software". ISSTA 2025.

**Artefactos:** https://github.com/purs3lab/ISSTA-2025-EMBOSS-Artifact  
**Zenodo:** doi.org/10.5281/zenodo.15200316 (SARIFs completos + spreadsheet de PRs)

## Proyectos Incluidos

| Proyecto | Repo | Defectos totales (paper) | Security | Criticality | Instancias en corpus |
|---|---|---|---|---|---|
| apache/nuttx | https://github.com/apache/nuttx | 35 | 24 | 0.69 | 5 |
| contiki-ng/contiki-ng | https://github.com/contiki-ng/contiki-ng | 34 | 24 | 0.67 | 5 |
| raysan5/raylib | https://github.com/raysan5/raylib | 33 | 33 | 0.70 | 6 |
| ARMmbed/mbed-os | https://github.com/ARMmbed/mbed-os | 32 | 22 | 0.72 | 4 |
| openlgtv/epk2extract | https://github.com/openlgtv/epk2extract | 29 | 27 | 0.45 | 4 |
| **TOTAL** | | **163** | **130** | | **24** |

## CWEs Objetivo

| CWE | Familia | Query CodeQL | Instancias en paper |
|---|---|---|---|
| CWE-476 | null-deref | `cpp/inconsistent-null-check` | 135 |
| CWE-134 | format-string | `cpp/missing-check-scanf` | 70 |
| CWE-120 | buffer-overflow | `cpp/unbounded-write` | 47 |
| CWE-190 | integer-overflow | `cpp/uncontrolled-allocation-size` | 49 |

## Distribución por Proyecto y CWE

| Proyecto | null-deref | buffer-overflow | integer-overflow | format-string | Total |
|---|---|---|---|---|---|
| apache_nuttx | 2 | 1 | 2 | 0 | 5 |
| contiki_ng_emboss | 3 | 2 | 0 | 0 | 5 |
| raylib | 1 | 3 | 2 | 0 | 6 |
| mbed_os | 2 | 1 | 1 | 0 | 4 |
| epk2extract | 1 | 2 | 0 | 1 | 4 |
| **TOTAL** | **9** | **9** | **5** | **1** | **24** |

## Esquema del Ground Truth

Los ficheros `ground_truth.yaml` siguen el esquema definido en
[selection_criteria.md](selection_criteria.md). Campos clave:

| Campo | Descripción |
|---|---|
| `id` | Identificador único del defecto (e.g. `NUTTX-DEFECT-001`) |
| `source` | Siempre `shen_et_al_issta_2025` para este corpus |
| `confirmed_by` | `pr_merged` — confirmación industrial |
| `pr_url` | URL del PR de fix aceptado en GitHub |
| `commit_fix` | SHA-40 del commit de fix |
| `commit_vulnerable` | SHA-40 del commit anterior (estado vulnerable) |
| `codeql_query` | Query CodeQL que detectó el defecto |
| `cwe_id` | CWE del defecto |
| `needs_manual_verification` | `true` si el commit_vulnerable necesita obtención manual |

## Entradas con Verificación Pendiente

Las entradas con `needs_manual_verification: true` tienen `commit_vulnerable: null`.
Para completarlas:

```bash
# Para cada entrada con needs_manual_verification: true
git -C /tmp/repos_b/<project> log --format="%H %P" <commit_fix> | awk '{print $2}'
```

Proyectos afectados:
- `raylib/ground_truth.yaml`: RAYLIB-DEFECT-004, RAYLIB-DEFECT-005
- `mbed_os/ground_truth.yaml`: MBEDOS-DEFECT-002, MBEDOS-DEFECT-004
- `epk2extract/ground_truth.yaml`: EPK2-DEFECT-001, EPK2-DEFECT-002, EPK2-DEFECT-003, EPK2-DEFECT-004

Para EPK2-DEFECT-004 también falta el PR URL — consultar el Zenodo artifact.

## Ejecución del Benchmark

```bash
# Clonar repositorios
for proj in apache/nuttx contiki-ng/contiki-ng raysan5/raylib ARMmbed/mbed-os openlgtv/epk2extract; do
    git clone https://github.com/$proj /tmp/repos_b/$(basename $proj)
done

# Ejecutar benchmark paralelo
python parallel_runner_b.py

# Validar ground truth
python scripts/validate_ground_truth.py \
    --gt corpus_b/apache_nuttx/ground_truth.yaml \
    --gt corpus_b/contiki_ng_emboss/ground_truth.yaml \
    --gt corpus_b/raylib/ground_truth.yaml \
    --gt corpus_b/mbed_os/ground_truth.yaml \
    --gt corpus_b/epk2extract/ground_truth.yaml
```

## Diferencias con Corpus A

| Aspecto | Corpus A (mbedTLS/wolfSSL) | Corpus B (EMBOSS) |
|---|---|---|
| Tipo de defecto | CVEs con ID oficial | Defectos EMBOSS confirmados por PR |
| Dominio | Crypto pura (TLS/SSL) | Embedded general (RTOS, networking, GUI) |
| Resultado esperado CodeQL | 0 TP (0% recall) | > 0 TP (recall medible) |
| Ground truth validation | NVD + security advisories | PRs merged en GitHub |
| CWEs | CWE-119/476/190/416 (crypto-context) | CWE-476/120/190/134 (general) |
