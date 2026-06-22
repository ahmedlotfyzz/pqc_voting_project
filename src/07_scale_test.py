"""
07_scale_test.py — Large-Scale Throughput and Latency Experiment
================================================================
Simulates 1,000 votes through the complete PQC signing pipeline
using concurrent threads to model real-world load conditions.

Measurements:
  - Per-vote signing latency (all 1000 samples)
  - Per-vote verification latency (all 1000 samples)
  - End-to-end wall-clock throughput under concurrent load
  - Full percentile profile: P50, P75, P90, P95, P99
  - 95% bootstrap confidence intervals on all key metrics
  - Block construction and Merkle root computation at scale

This goes beyond the Phase 3 guide requirement ("simulate 1000 votes")
by adding concurrency, statistical rigour, and CI reporting.
"""

import oqs
import os
import json
import time
import hashlib
import random
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

KEYS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'keys')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

SCHEME      = "Dilithium2"
N_VOTES     = 1000
BATCH_SIZE  = 50       # votes per block
N_THREADS   = 4        # concurrent signing threads
CANDIDATES  = ["Candidate_A", "Candidate_B", "Candidate_C"]
ELECTION_ID = "ELECTION_2025_EG_001"
BOOTSTRAP_N = 2000     # bootstrap resamples for CI


# ══════════════════════════════════════════════════════════════════════════════
# Key pool — pre-generate keys for N_VOTES simulated voters
# ══════════════════════════════════════════════════════════════════════════════

def generate_key_pool(n: int) -> list[dict]:
    """Generate n Dilithium2 key pairs. Reuses the 5 real keys in rotation."""
    real_voters = ["voter_001","voter_002","voter_003","voter_004","voter_005"]
    pool = []
    for i in range(n):
        voter_id = f"scale_voter_{i+1:04d}"
        # Rotate through real keys to avoid regenerating 1000 key pairs
        real_id  = real_voters[i % 5]
        pub_path = os.path.join(KEYS_DIR, f"{real_id}_public.bin")
        sec_path = os.path.join(KEYS_DIR, f"{real_id}_secret.bin")
        with open(pub_path, "rb") as f: pk = f.read()
        with open(sec_path, "rb") as f: sk = f.read()
        pool.append({"voter_id": voter_id, "public_key": pk, "secret_key": sk})
    return pool


# ══════════════════════════════════════════════════════════════════════════════
# Vote signing worker
# ══════════════════════════════════════════════════════════════════════════════

def sign_vote(voter: dict, choice: str) -> dict:
    payload = {
        "election_id": ELECTION_ID,
        "voter_id":    voter["voter_id"],
        "choice":      choice,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    payload_hash  = hashlib.sha256(payload_bytes).hexdigest()

    t0      = time.perf_counter()
    signer  = oqs.Signature(SCHEME, voter["secret_key"])
    sig     = signer.sign(payload_bytes)
    sign_ms = (time.perf_counter() - t0) * 1000

    return {
        "voter_id":     voter["voter_id"],
        "public_key":   voter["public_key"],
        "payload":      payload,
        "payload_hash": payload_hash,
        "payload_bytes": payload_bytes,
        "signature":    sig,
        "sign_ms":      round(sign_ms, 4),
    }


def verify_vote(record: dict) -> tuple[bool, float]:
    t0       = time.perf_counter()
    verifier = oqs.Signature(SCHEME)
    valid    = verifier.verify(
        record["payload_bytes"], record["signature"], record["public_key"]
    )
    verify_ms = (time.perf_counter() - t0) * 1000
    return bool(valid), round(verify_ms, 4)


# ══════════════════════════════════════════════════════════════════════════════
# Block builder (Merkle)
# ══════════════════════════════════════════════════════════════════════════════

def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"empty").hexdigest()
    layer = [bytes.fromhex(h) for h in hashes]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i]+layer[i+1]).digest()
                 for i in range(0, len(layer), 2)]
    return layer[0].hex()

def build_block(index: int, vote_hashes: list[str], prev_hash: str) -> dict:
    ts  = datetime.now(timezone.utc).isoformat()
    mr  = merkle_root(vote_hashes)
    bh  = hashlib.sha256(json.dumps({
        "index": index, "timestamp": ts,
        "merkle_root": mr, "previous_hash": prev_hash,
    }, sort_keys=True).encode()).hexdigest()
    return {"index":index,"timestamp":ts,"vote_count":len(vote_hashes),
            "merkle_root":mr,"previous_hash":prev_hash,"block_hash":bh}


# ══════════════════════════════════════════════════════════════════════════════
# Statistical helpers
# ══════════════════════════════════════════════════════════════════════════════

def percentile(data: list[float], p: float) -> float:
    s = sorted(data)
    k = (len(s)-1) * p / 100
    lo, hi = int(k), min(int(k)+1, len(s)-1)
    return round(s[lo] + (s[hi]-s[lo]) * (k-lo), 4)

def bootstrap_ci(data: list[float], stat_fn, n=BOOTSTRAP_N, alpha=0.05) -> tuple[float,float]:
    rng      = random.Random(42)
    samples  = [stat_fn(rng.choices(data, k=len(data))) for _ in range(n)]
    samples.sort()
    lo_idx   = int(alpha/2 * n)
    hi_idx   = int((1-alpha/2) * n)
    return round(samples[lo_idx],4), round(samples[hi_idx],4)

def stats_block(data: list[float], label: str) -> dict:
    mn   = statistics.mean(data)
    med  = statistics.median(data)
    sd   = statistics.stdev(data)
    ci_lo, ci_hi = bootstrap_ci(data, statistics.mean)
    return {
        "metric":  label,
        "n":       len(data),
        "mean":    round(mn,  4),
        "median":  round(med, 4),
        "stdev":   round(sd,  4),
        "p50":     percentile(data, 50),
        "p75":     percentile(data, 75),
        "p90":     percentile(data, 90),
        "p95":     percentile(data, 95),
        "p99":     percentile(data, 99),
        "min":     round(min(data), 4),
        "max":     round(max(data), 4),
        "ci95_lo": ci_lo,
        "ci95_hi": ci_hi,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Main experiment
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*66}")
    print(f"  Phase 3 — Scale Test: {N_VOTES} votes, {N_THREADS} threads")
    print(f"  Scheme: {SCHEME}  |  Batch size: {BATCH_SIZE} votes/block")
    print(f"{'='*66}\n")

    # ── Key pool ─────────────────────────────────────────────────────────
    print(f"  Loading key pool ({N_VOTES} voters from 5 real key pairs)...")
    key_pool = generate_key_pool(N_VOTES)
    choices  = [random.choice(CANDIDATES) for _ in range(N_VOTES)]
    print(f"  Key pool ready.\n")

    # ── Phase A: Concurrent signing ───────────────────────────────────────
    print(f"  [ Phase A — Concurrent signing ({N_THREADS} threads) ]\n")
    signed_records = []
    sign_times     = []
    lock           = threading.Lock()

    wall_sign_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=N_THREADS) as executor:
        futures = {
            executor.submit(sign_vote, key_pool[i], choices[i]): i
            for i in range(N_VOTES)
        }
        done = 0
        for future in as_completed(futures):
            record = future.result()
            with lock:
                signed_records.append(record)
                sign_times.append(record["sign_ms"])
                done += 1
                if done % 200 == 0:
                    elapsed = time.perf_counter() - wall_sign_start
                    rate    = done / elapsed
                    print(f"  Signed {done:>5}/{N_VOTES}  "
                          f"elapsed: {elapsed:.1f}s  rate: {rate:.0f} votes/s")

    wall_sign_total = time.perf_counter() - wall_sign_start
    sign_throughput = N_VOTES / wall_sign_total
    print(f"\n  Signing complete: {wall_sign_total:.2f}s  "
          f"throughput: {sign_throughput:.1f} votes/sec\n")

    # ── Phase B: Sequential verification ─────────────────────────────────
    print(f"  [ Phase B — Verification (sequential, all {N_VOTES} votes) ]\n")
    verify_times = []
    all_valid    = True

    wall_ver_start = time.perf_counter()
    for i, record in enumerate(signed_records):
        valid, vt = verify_vote(record)
        verify_times.append(vt)
        if not valid:
            all_valid = False
            print(f"  [!!] Verification FAILED for {record['voter_id']}")
        if (i+1) % 200 == 0:
            print(f"  Verified {i+1:>5}/{N_VOTES}  all_valid={all_valid}")

    wall_ver_total  = time.perf_counter() - wall_ver_start
    ver_throughput  = N_VOTES / wall_ver_total
    print(f"\n  Verification complete: {wall_ver_total:.2f}s  "
          f"throughput: {ver_throughput:.1f} votes/sec  "
          f"all_valid={all_valid}\n")

    # ── Phase C: Block construction ───────────────────────────────────────
    print(f"  [ Phase C — Block construction ({BATCH_SIZE} votes/block) ]\n")
    blocks     = []
    prev_hash  = "0" * 64
    n_blocks   = 0
    block_times= []

    for i in range(0, N_VOTES, BATCH_SIZE):
        batch      = signed_records[i:i+BATCH_SIZE]
        vote_hashes= [r["payload_hash"] for r in batch]
        t0         = time.perf_counter()
        block      = build_block(n_blocks+1, vote_hashes, prev_hash)
        block_ms   = (time.perf_counter()-t0)*1000
        prev_hash  = block["block_hash"]
        blocks.append(block)
        block_times.append(block_ms)
        n_blocks  += 1

    avg_block_ms = sum(block_times)/len(block_times)
    print(f"  Blocks built   : {n_blocks}")
    print(f"  Avg block time : {avg_block_ms:.4f} ms\n")

    # ── Phase D: End-to-end e2e latency ───────────────────────────────────
    e2e_times = [st + vt for st, vt in zip(sign_times, verify_times)]

    # ── Statistics ────────────────────────────────────────────────────────
    sign_stats  = stats_block(sign_times,   "signing_ms")
    verify_stats= stats_block(verify_times, "verification_ms")
    e2e_stats   = stats_block(e2e_times,    "e2e_ms")

    # ── Print results table ───────────────────────────────────────────────
    print(f"{'='*66}")
    print(f"  LATENCY RESULTS — {N_VOTES} votes, {N_THREADS} threads")
    print(f"{'='*66}")
    header = f"  {'Metric':<22} {'Mean':>8} {'Median':>8} {'P90':>8} {'P95':>8} {'P99':>8}"
    print(header)
    print(f"  {'-'*64}")
    for s in [sign_stats, verify_stats, e2e_stats]:
        print(f"  {s['metric']:<22} "
              f"{s['mean']:>8.4f} {s['median']:>8.4f} "
              f"{s['p90']:>8.4f} {s['p95']:>8.4f} {s['p99']:>8.4f}  ms")

    print(f"\n  95% CI on mean signing   : [{sign_stats['ci95_lo']:.4f}, "
          f"{sign_stats['ci95_hi']:.4f}] ms")
    print(f"  95% CI on mean verify    : [{verify_stats['ci95_lo']:.4f}, "
          f"{verify_stats['ci95_hi']:.4f}] ms")

    print(f"\n{'='*66}")
    print(f"  THROUGHPUT RESULTS")
    print(f"{'='*66}")
    print(f"  Signing throughput   : {sign_throughput:>10,.1f} votes/sec")
    print(f"  Verify  throughput   : {ver_throughput:>10,.1f} votes/sec")
    print(f"  Blocks committed     : {n_blocks:>10}")
    print(f"  Avg block build time : {avg_block_ms:>10.4f} ms")
    print(f"  All signatures valid : {all_valid}")
    print(f"{'='*66}\n")

    # ── Save ──────────────────────────────────────────────────────────────
    report = {
        "experiment":       "scale_test_1000_votes",
        "scheme":           SCHEME,
        "n_votes":          N_VOTES,
        "n_threads":        N_THREADS,
        "batch_size":       BATCH_SIZE,
        "n_blocks":         n_blocks,
        "all_valid":        all_valid,
        "sign_throughput":  round(sign_throughput,  2),
        "verify_throughput":round(ver_throughput,   2),
        "avg_block_ms":     round(avg_block_ms,     4),
        "sign_stats":       sign_stats,
        "verify_stats":     verify_stats,
        "e2e_stats":        e2e_stats,
        "run_at":           datetime.now(timezone.utc).isoformat(),
    }
    out = os.path.join(RESULTS_DIR, "scale_test_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report: {out}\n")


if __name__ == "__main__":
    main()
