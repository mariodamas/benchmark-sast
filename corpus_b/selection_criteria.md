# Criterios de Selección — Corpus B (EMBOSS)

## Contexto

Este documento formaliza los criterios usados para seleccionar instancias del
corpus EMBOSS (Shen et al. ISSTA 2025) para el benchmark SAST CodeQL vs Coverity.

Los criterios son **no negociables**: cualquier modificación del corpus que
relaje estos criterios requiere justificación explícita y actualización de
este fichero.

---

## Criterios de Inclusión (todos deben cumplirse)

### C1 — PR Merged (Confirmación Industrial)

Solo se incluyen defectos cuya corrección fue aceptada como PR en el repositorio
oficial del proyecto. Un PR merged implica que:
- Al menos un maintainer del proyecto revisó el fix
- El fix fue considerado correcto y necesario
- El defecto existía en el commit inmediatamente anterior al merge

**Evidencia requerida:** `pr_url` apuntando a un PR con estado `merged` en GitHub.

### C2 — Tipo Security (Tag Security en la Query CodeQL)

Solo defectos clasificados como `security` en el EMBOSS paper (Tabla 5, columna
"Security PRs Accepted"). Las queries prioritarias son:

| Query | CWE | Instancias en paper |
|---|---|---|
| `cpp/inconsistent-null-check` | CWE-476 | 135 |
| `cpp/missing-check-scanf` | CWE-134 | 70 |
| `cpp/uncontrolled-allocation-size` | CWE-190 | 49 |
| `cpp/unbounded-write` | CWE-120 | 47 |

Queries con tag `security` (no solo `correctness`) en el CodeQL query suite estándar.

### C3 — Familias CWE Objetivo

Solo se incluyen defectos de estas familias CWE:
- `null-deref` (CWE-476)
- `buffer-overflow` (CWE-120, CWE-122, CWE-125)
- `integer-overflow` (CWE-190, CWE-191)
- `format-string` (CWE-134)

Familias **excluidas**: `side-channel`, `use-after-free`, `race-condition`,
`taint` (demasiado dependiente del análisis inter-procedural para ser reproducible).

### C4 — Código Fuente C/C++ Principal (no tests, no examples)

El fichero afectado debe ser:
- Código fuente C o C++ (extensiones `.c`, `.cpp`, `.h`, `.hpp`)
- Parte del código de producción del proyecto
- **Excluido:** ficheros en directorios `test/`, `tests/`, `examples/`, `docs/`,
  `tools/` o con sufijo `_test.c`

Razón: los tests pueden tener patrones de código intencionalmente "inseguros" para
verificar comportamiento de error; los examples pueden no representar código embebido.

### C5 — Diff Claro en el Fichero Afectado

El PR de fix debe tener un diff observable en el fichero C/C++ afectado que:
- Añada un check de NULL, bound, o tipo
- Cambie un tipo de dato para evitar overflow
- Reemplace una función insegura (sprintf → snprintf)

**No aceptable:** PRs que solo cambian comentarios, whitespace, o ficheros de
configuración sin modificar el código C/C++ en la localización del defecto.

### C6 — Commit Pair Verificable

El par (commit_vulnerable, commit_fix) debe ser obtenible mediante:
- `git log` en el repositorio oficial
- GitHub API (commits endpoint)

Entradas con `needs_manual_verification: true` son provisionalmente incluidas
pero **no deben ejecutarse** hasta que el commit_vulnerable esté confirmado.

---

## Criterios de Exclusión (cualquiera excluye la instancia)

### E1 — Código Vendoreado de Terceros

Defectos en código copiado de terceros dentro del repositorio (directorios
`third_party/`, `vendor/`, `external/`, `libs/`) se excluyen, excepto cuando:
- El proyecto es el mantenedor principal de ese código
- El defecto fue reportado y aceptado por ese proyecto (no el código original)

Ejemplo: `src/external/jar_mod.h` en raylib es código de terceros, pero el PR
fue aceptado por raylib y el fix está en el repo de raylib → **incluido**.

### E2 — Defectos en Código de Test

Ficheros de test no representan comportamiento de producción. Cualquier fichero
en directorio de test queda excluido.

### E3 — Defectos sin Localización Precisa

Si no es posible identificar la función o línea aproximada del defecto con
suficiente precisión para que la herramienta pueda localizarlo (ambigüedad
> ±50 líneas en un fichero de múltiples defectos), la instancia se excluye.

### E4 — FN Estructurales

Defectos que por su naturaleza no son detectables mediante análisis estático
de flujo de datos (timing side-channels, race conditions no serializables)
se marcan como `structural_fn: true` y **se excluyen del denominador de recall**.

En este corpus (EMBOSS) no se esperan FN estructurales dado el tipo de queries
usadas (null-deref, buffer-overflow, integer-overflow, format-string), pero el
campo se mantiene por compatibilidad de esquema.

---

## Proceso de Selección

1. **Fuente primaria:** EMBOSS artifact spreadsheet (Responsible Disclosure sheet)
   + SARIFs de Zenodo (doi.org/10.5281/zenodo.15200316)
2. **Filtro por proyecto:** Top-5 de Tabla 5 del paper (mayor número de defectos)
3. **Filtro por tipo:** Solo instancias marcadas como "security" en el spreadsheet
4. **Filtro por query:** Priorizar las 4 queries con mayor número de instancias
5. **Verificación PR:** Confirmar que el PR está merged en GitHub
6. **Obtención de commits:** GitHub API → merge_commit_sha + parent SHA
7. **Validación de fichero:** Confirmar que el fichero afectado existe en el commit

Número mínimo de instancias por proyecto: **4**
Número máximo de instancias por proyecto: **8**

---

## Compatibilidad de Esquema con Corpus A

El esquema YAML extiende (no reemplaza) el del Corpus A:

| Campo | Corpus A (CVE) | Corpus B (EMBOSS) |
|---|---|---|
| `id` | `MBEDTLS-CVE-2021-XXXX` | `NUTTX-DEFECT-001` |
| `cve` | Requerido | No aplica (ausente) |
| `cwe` | `CWE-476` | Ausente (sustituido por `cwe_id`) |
| `cwe_id` | Ausente | `CWE-476` |
| `cvss` | Requerido | No aplica (ausente) |
| `source` | Ausente | `shen_et_al_issta_2025` |
| `confirmed_by` | Ausente | `pr_merged` |
| `pr_url` | Opcional | Requerido |
| `codeql_query` | Ausente | Requerido |
| `structural_fn` | Requerido | Requerido |
| `commit_fix/vulnerable` | Requerido | Requerido |

El validador (`scripts/validate_ground_truth.py`) detecta el tipo de corpus
por la presencia del campo `source` y ajusta los campos requeridos.
