# Reproducibility checklist

This document maps each item the editor requested to its location in this repository.

| Editor request | Provided in |
|---|---|
| Benchmark scripts | `src/benchmark.py`, `src/07_scale_test.py`, `src/10_evaluation.py` |
| Raw latency logs | `results/evaluation_report.json`, `results/scale_test_report.json` |
| Adversarial-input generator | `src/09_attack_suite.py` |
| Random seeds | `seed = 42` (documented in `ENVIRONMENT.md`, set in each randomised script) |
| Payload examples | `docs/example_vote_record.json` |
| Exact liboqs / liboqs-python versions | `ENVIRONMENT.md` (liboqs 0.11.0, liboqs-python 0.14.1) |
| Python dependencies | `requirements.txt` |
| Validator stake configuration | `ENVIRONMENT.md` (0.50 / 0.30 / 0.20), `src/05_consensus.py` |
| CI / percentile computation scripts | `src/10_evaluation.py` (NumPy linear-interpolation percentiles; t-distribution and bootstrap CIs) |
| Scripts that generate every table and figure | `src/` (see mapping table in `README.md`), `src/11_dashboard.py` |

## Notes addressing specific editorial comments

**Percentiles (P90 vs P95).** Percentiles are computed with
`numpy.percentile(data, q, method="linear")`. The serial benchmark and the
concurrent scale test are two distinct experiments; their percentile values differ
accordingly and are reported in separate tables.

**Confidence intervals.** The serial-benchmark CI (n = 500) uses the t-distribution
(df = 499). The concurrent-test CI (n = 1,000) uses 10,000-sample bootstrap
resampling. No outliers were removed.

**Throughput vs. latency.** Aggregate throughput is measured as wall-clock
records/second across the 4-thread pool, while P95 latency is a per-operation
percentile. The two are not directly interchangeable because of thread-level
parallelism and scheduling overhead; both are reported independently.

**Legitimate vs. adversarial inputs.** The 1,000 legitimate votes and the 550
adversarial inputs are disjoint sets. The 550 adversarial inputs comprise 5 replay,
500 flood, 15 stripping, 25 bit-corruption, and 5 signature-swap cases.

**Storage units.** All storage figures use binary units (1 GiB = 2^30 bytes). The
national-scale JSON projection is 327 GiB (351 GB decimal); CBOR is 167 GiB, a
byte-level reduction of 48.8% (1 - 2,680 / 5,239).
