#!/usr/bin/env python3
"""
tests/test_pipeline_e2e.py
===========================
Test end-to-end del pipeline completo usando datos mock.
Ejecuta: mock_runner → deduplicador → métricas → cross-project
y verifica que los resultados coinciden con los valores esperados.

Ejecutar sin ninguna dependencia de herramientas externas:
    python tests/test_pipeline_e2e.py

Salida:
    PASS / FAIL por cada aserción, con valores obtenidos vs esperados.
"""

import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Ruta base del repo
REPO_ROOT = Path(__file__).parent.parent
GROUND_TRUTH_MBEDTLS = REPO_ROOT / "corpus" / "mbedtls" / "ground_truth.yaml"

# Valores esperados con el escenario mock v2 (GT con 21 evaluables + 5 FN estructurales)
# El mock_runner solo genera datos para 5 CVEs → los 16 restantes producen 0 findings → FN.
# Esto es correcto: el test verifica que el pipeline maneja CVEs sin datos como FN,
# que es exactamente lo que ocurrirá con las instancias que las herramientas no detecten.
EXPECTED = {
    "N_evaluable": 21,       # GT v2: 21 evaluables
    "N_structural_fn": 5,    # GT v2: 5 FN estructurales
    "TP_CodeQL": 4,          # Mock: 4 de 5 CVEs con datos → TP
    "TP_Coverity": 4,
    "TP_overlap": 3,
    "TP_unique_CodeQL": 1,
    "TP_unique_Coverity": 1,
    "TP_union": 5,
    "FN_CodeQL": 17,         # 1 mock FN + 16 CVEs sin datos mock
    "FN_Coverity": 17,
    "Recall_CodeQL": 0.1905,
    "Recall_Coverity": 0.1905,
    "Recall_union": 0.2381,
    "Marginal_gain_recall": 0.0476,
}


class TestResult:
    def __init__(self):
        self.passed = []
        self.failed = []

    def check(self, name: str, expected, actual, tolerance: float = 1e-6):
        if isinstance(expected, float):
            ok = abs(expected - actual) <= tolerance
        else:
            ok = expected == actual
        if ok:
            self.passed.append(name)
            print(f"  ✓ PASS  {name}: {actual}")
        else:
            self.failed.append(name)
            print(f"  ✗ FAIL  {name}: expected={expected}, got={actual}")

    def summary(self) -> bool:
        total = len(self.passed) + len(self.failed)
        print(f"\n{'='*60}")
        print(f"RESULTADO: {len(self.passed)}/{total} tests pasados")
        if self.failed:
            print(f"FALLIDOS: {self.failed}")
        print("="*60)
        return len(self.failed) == 0


def run_cmd(cmd: list, cwd=None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=cwd or REPO_ROOT
    )
    if result.returncode != 0:
        log.error(f"CMD FAILED: {' '.join(str(c) for c in cmd)}")
        log.error(f"STDERR: {result.stderr[:1000]}")
    return result


def main():
    print("\n" + "="*60)
    print("TEST E2E — Pipeline SAST Benchmark (datos mock)")
    print("="*60)

    tr = TestResult()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        print(f"\nDirectorio temporal: {tmpdir}")

        # ----------------------------------------------------------------
        # PASO 1: Generar datos mock
        # ----------------------------------------------------------------
        print("\n[1/5] Generando datos mock...")
        r = run_cmd([
            sys.executable, "tests/mock_runner.py",
            "--output-dir", str(tmpdir),
            "--project", "mbedtls",
        ])
        if r.returncode != 0:
            print(f"✗ FATAL: mock_runner falló\n{r.stderr}")
            sys.exit(1)
        print("  → Mock data generado")

        # ----------------------------------------------------------------
        # PASO 2: Deduplicación
        # ----------------------------------------------------------------
        print("\n[2/5] Ejecutando deduplicación...")
        dedup_out = tmpdir / "deduplicated" / "mbedtls"
        r = run_cmd([
            sys.executable, "deduplicator/dedup_findings.py",
            "--ground-truth", str(GROUND_TRUTH_MBEDTLS),
            "--codeql-results", str(tmpdir / "raw" / "codeql" / "mbedtls"),
            "--coverity-results", str(tmpdir / "raw" / "coverity" / "mbedtls"),
            "--output-dir", str(dedup_out),
            "--line-window", "10",
        ])
        if r.returncode != 0:
            print(f"✗ FATAL: dedup_findings falló\n{r.stderr}")
            sys.exit(1)
        print("  → Deduplicación completada")

        # Verificar que se generaron los JSONs esperados
        dedup_files = list(dedup_out.glob("*.json"))
        print(f"  Ficheros generados: {[f.name for f in dedup_files]}")

        # ----------------------------------------------------------------
        # PASO 3: Métricas
        # ----------------------------------------------------------------
        print("\n[3/5] Calculando métricas...")
        metrics_out = tmpdir / "metrics" / "mbedtls"
        r = run_cmd([
            sys.executable, "metrics/compute_metrics.py",
            "--dedup-dir", str(dedup_out),
            "--output-dir", str(metrics_out),
            "--kloc", "60",
            "--phase", "primary",
        ])
        if r.returncode != 0:
            print(f"✗ FATAL: compute_metrics falló\n{r.stderr}")
            sys.exit(1)

        # Cargar métricas calculadas
        il_path = metrics_out / "instance_level_metrics.json"
        if not il_path.exists():
            print(f"✗ FATAL: {il_path} no generado")
            sys.exit(1)

        with open(il_path) as f:
            il = json.load(f)

        # ----------------------------------------------------------------
        # PASO 4: Verificar métricas instance-level
        # ----------------------------------------------------------------
        print("\n[4/5] Verificando métricas instance-level...")
        for key, expected_val in EXPECTED.items():
            actual_val = il.get(key, None)
            if actual_val is None:
                print(f"  ✗ FAIL  {key}: clave no encontrada en métricas")
                tr.failed.append(key)
                continue
            tr.check(key, expected_val, actual_val, tolerance=0.001)

        # Verificar CVEs únicos
        tr.check(
            "CVE_unique_CodeQL_is_CVE-2020-36421",
            expected=True,
            actual="CVE-2020-36421" in il.get("CVEs_unique_CodeQL", []),
        )
        tr.check(
            "CVE_unique_Coverity_is_CVE-2022-46392",
            expected=True,
            actual="CVE-2022-46392" in il.get("CVEs_unique_Coverity", []),
        )

        # Verificar FN estructurales no en denominador
        tr.check(
            "structural_fns_count",
            expected=5,   # GT v2: 5 FN estructurales (CWE-208/203)
            actual=il.get("N_structural_fn", -1),
        )

        # ----------------------------------------------------------------
        # PASO 5: Verificar métricas finding-level
        # ----------------------------------------------------------------
        print("\n[5/5] Verificando métricas finding-level...")
        fl_path = metrics_out / "finding_level_metrics.json"
        with open(fl_path) as f:
            fl = json.load(f)

        # FP finding-level: solo el finding que persiste en CVE-2022-46393 (CodeQL)
        # y el RESOURCE_LEAK en CVE-2020-36421 (Coverity, "other" family, pasa filtro de archivo)
        tr.check(
            "FP_finding_CodeQL_at_least_1",
            expected=True,
            actual=fl.get("total_FP_findings_CodeQL", 0) >= 1,
        )
        # Coverity tiene 1 FP: RESOURCE_LEAK en bignum.c (CVE-2020-36421).
        # Pasa el pre-filtro (mismo archivo + cwe_family="other" es comodín) y persiste en S.
        # Esto es comportamiento CORRECTO del deduplicador: el FP es real.
        tr.check(
            "FP_finding_Coverity_at_least_1",
            expected=True,
            actual=fl.get("total_FP_findings_Coverity", 0) >= 1,
        )
        tr.check(
            "review_cost_hours_codeql_positive",
            expected=True,
            actual=fl.get("review_cost_hours_CodeQL", 0) > 0,
        )

    success = tr.summary()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
