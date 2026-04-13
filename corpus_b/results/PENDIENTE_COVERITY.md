# PENDIENTE: Fase C — Coverity Linux

Este fichero registra el estado de la integración Coverity para corpus_b.

## Estado actual

- **Fase A** (build): pendiente de ejecutar en WSL2
- **Fase B** (CodeQL): pendiente de ejecutar en WSL2
- **Fase C** (Coverity): **BLOQUEADA** — Coverity no disponible en Linux/WSL2

## Bloqueante

Coverity está instalado en **Windows** (host), no en WSL2.
El runner (`corpus_b/runner/parallel_runner.py`) está diseñado para ejecutar
en WSL2 donde las herramientas deben ser accesibles como binarios Unix.

Opciones disponibles:

### Opción A — Instalar Coverity en WSL2 (recomendada)

Cuando se disponga de licencia Linux:

```bash
# 1. Descargar instalador desde portal Synopsys
# 2. Copiar a WSL2
cp /mnt/c/Users/mario/Downloads/cov-analysis-linux64-*.sh /tmp/coverity_installer.sh

# 3. Ejecutar script de instalación
bash corpus_b/scripts/install_coverity_linux.sh --installer /tmp/coverity_installer.sh

# 4. Ejecutar Fase C
python corpus_b/runner/parallel_runner.py --phase C
```

Script de ayuda: `corpus_b/scripts/install_coverity_linux.sh`

### Opción B — Coverity en Windows + exportar resultados a WSL2

Si solo se dispone de licencia Windows:

1. Ejecutar `cov-build` y `cov-analyze` en PowerShell/CMD sobre los repos clonados en Windows
2. Exportar JSON con `cov-format-errors --json-output-v8`
3. Copiar JSON a la ruta esperada por el runner:
   ```
   corpus_b/results/coverity/<project>/<instance_id>/<V|S>.json
   ```
4. Clasificar desde WSL2:
   ```bash
   python corpus_b/runner/run_coverity.py --project apache_nuttx --classify
   ```

### Opción C — Evaluar solo CodeQL (resultado parcial)

Si no se dispone de Coverity, el benchmark puede completarse con solo CodeQL:

```bash
# Ejecutar benchmark sin Coverity
python corpus_b/runner/parallel_runner.py --skip-coverity

# Calcular métricas solo CodeQL
python shared/metrics/compute_metrics.py --corpus b --tool codeql
```

La métrica `Marginal_gain` requiere ambas herramientas, pero el
`Recall_CodeQL` se puede publicar como resultado parcial.

## Checklist para activar Coverity

- [ ] Obtener licencia Coverity Linux (free tier o académica)
  - https://community.synopsys.com/s/article/Coverity-Downloads
  - Alternativa: Coverity Student License via Synopsys Academic Program
- [ ] Ejecutar `bash corpus_b/scripts/install_coverity_linux.sh`
- [ ] Verificar: `cov-build --version`
- [ ] Verificar: `COVERITY_HOME` en `.env.benchmark`
- [ ] Ejecutar Fase A con Coverity habilitado (reconstruir cov_dirs):
  ```bash
  python corpus_b/runner/parallel_runner.py --phase A
  ```
  (Si los cov_dirs ya existen de una ejecución anterior de Windows, copiarlos)
- [ ] Ejecutar Fase C:
  ```bash
  python corpus_b/runner/parallel_runner.py --phase C
  ```
- [ ] Verificar clasificaciones en `corpus_b/results/coverity_classifications.json`
- [ ] Calcular métricas finales:
  ```bash
  python shared/metrics/compute_metrics.py --corpus b
  ```

## Proyectos e instancias corpus_b

| Proyecto       | Instancias | CWE principal   |
|----------------|-----------|-----------------|
| apache_nuttx   | 5         | null-deref      |
| contiki_ng     | 4         | null-deref      |
| raylib         | 5         | null-deref/buf  |
| mbed_os        | 4         | null-deref      |
| epk2extract    | 4         | null-deref      |
| **Total**      | **22**    |                 |

Nota: el total excluye instancias con `needs_manual_verification: true`.
Ejecutar `python shared/validate_ground_truth.py corpus_b/corpus/*/ground_truth.yaml`
para el recuento exacto.

## Referencia

- Runner: `corpus_b/runner/parallel_runner.py`
- Config: `.env.benchmark`
- Setup WSL2: `corpus_b/scripts/setup_wsl2.sh`
- Instalación Coverity: `corpus_b/scripts/install_coverity_linux.sh`
