# Post-Quantum Blockchain for Secure Data Transmission

**Reproducibility artifacts for:**
*"Post-Quantum Blockchain for Secure Data Transmission: Design and Empirical Evaluation Using CRYSTALS-Dilithium2"* (INASS Express, Paper ID ex-20260050).

This repository contains the complete implementation, raw result logs, and analysis
scripts required to reproduce every table and figure in the manuscript. It is released
in response to the editorial request for reproducible artifacts.

---

## 1. Overview

The project implements and empirically evaluates a four-layer quantum-resistant
blockchain built on **CRYSTALS-Dilithium2** (NIST FIPS 204, ML-DSA-44) with a
**Q-PnV-inspired** consensus mechanism. Evaluation covers cryptographic benchmarking,
concurrent throughput, a quantum-inspired attack simulation, consensus validation, an
adversarial attack suite, and storage analysis.

## 2. Repository structure

```
.
├── README.md                  # this file
├── requirements.txt           # exact Python dependencies
├── ENVIRONMENT.md             # hardware/software environment + versions
├── LICENSE                    # MIT license
├── src/                       # all source scripts (run in numeric order)
│   ├── 01_keygen.py           # Dilithium2 key generation
│   ├── 02_sign.py             # record signing (Algorithm 1)
│   ├── 03_verify.py           # dual-layer verification (Algorithm 2)
│   ├── 04_blockchain.py       # block construction + hash-chain linking
│   ├── 04_attack.py           # quantum-inspired attack simulation
│   ├── 05_consensus.py        # Q-PnV weighted-stake consensus
│   ├── 06_audit.py            # chain integrity / tamper-detection audit
│   ├── 07_scale_test.py       # concurrent throughput test (n=1000, 4 threads)
│   ├── 08_storage.py          # storage projection (JSON vs CBOR)
│   ├── 09_attack_suite.py     # five-vector adversarial suite (seed=42)
│   ├── 10_evaluation.py       # aggregates all results, computes CIs/percentiles
│   ├── 11_dashboard.py        # generates summary figures
│   └── benchmark.py           # standalone serial latency benchmark (n=500)
├── results/                   # raw result logs (JSON) used in the paper
│   ├── evaluation_report.json
│   ├── scale_test_report.json
│   └── storage_report.json
└── figures/                   # generated figures
```

## 3. Quick start

```bash
# 1. create a clean environment (Python 3.11)
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. install dependencies
pip install -r requirements.txt

# 3. run the full pipeline in order
python src/01_keygen.py
python src/02_sign.py
python src/03_verify.py
python src/04_blockchain.py
python src/04_attack.py
python src/05_consensus.py
python src/06_audit.py
python src/07_scale_test.py
python src/08_storage.py
python src/09_attack_suite.py
python src/10_evaluation.py        # produces evaluation_report.json
python src/11_dashboard.py         # produces figures
```

All randomised steps use a fixed seed (`seed = 42`) for reproducibility.

## 4. Mapping: paper tables/figures -> scripts & logs

| Paper item | Produced by | Raw log |
|---|---|---|
| Table 2 (latency, percentiles, CI) | `benchmark.py`, `10_evaluation.py` | `results/evaluation_report.json` |
| Table 4 / Fig. 3 (throughput, n=1000) | `07_scale_test.py` | `results/scale_test_report.json` |
| Table 3 / Fig. 2 (quantum simulation) | `04_attack.py` | (regenerated on run) |
| Table 5 / Fig. 4 (Q-PnV consensus) | `05_consensus.py` | (regenerated on run) |
| Table 6 (adversarial suite) | `09_attack_suite.py` | (regenerated on run) |
| Fig. 5 / Fig. 6 (storage) | `08_storage.py` | `results/storage_report.json` |
| Table 7 (deployment readiness) | `10_evaluation.py` | `results/evaluation_report.json` |

## 5. Statistical methodology

- **Percentiles** (P75/P90/P95/P99) are computed with NumPy linear interpolation
  (`numpy.percentile(..., method="linear")`).
- **95% CI on the mean** for the serial benchmark (n=500) uses the t-distribution
  (df = n-1); for the concurrent test (n=1000) it uses 10,000-sample bootstrap
  resampling. Both methods are reported explicitly in the paper.
- **Effect size** between signing and verification uses the Mann-Whitney U test and
  Cohen's d.
- No outliers were removed; all raw samples are retained.

## 6. Citation

If you use these artifacts, please cite the paper (full reference to be added on
publication). DOI: `10.22266/inassexpress.20xx.00x`.

## 7. License

Released under the MIT License (see `LICENSE`). All figures, tables, and code are
original works produced by the authors.
