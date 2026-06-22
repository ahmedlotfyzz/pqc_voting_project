"""
09_attack_suite.py — Comprehensive Security Attack Suite
=========================================================
Tests the system against 5 attack categories not covered in Phase 1/2:

  Attack 1 — Replay attack:
    A legitimately signed vote from Election_A is resubmitted to
    Election_B. The election_id in the payload differs from what
    the signature was computed over — verification fails.

  Attack 2 — Vote flooding:
    500 invalid votes (random payloads, no valid signature) are
    submitted in rapid succession. All are rejected. Measures
    rejection throughput.

  Attack 3 — Signature stripping:
    Valid payload submitted with an empty/missing signature.
    System must not accept unsigned votes.

  Attack 4 — Payload corruption after signing:
    Bit-level corruption of payload bytes before verification.
    Tests that even 1-bit changes are caught.

  Attack 5 — Cross-voter signature reuse:
    voter_001's signature submitted with voter_002's payload.
    Tests that signatures are bound to specific voters.
"""

import oqs
import os
import json
import hashlib
import random
import time
from datetime import datetime, timezone

KEYS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'keys')
VOTES_DIR   = os.path.join(os.path.dirname(__file__), '..', 'votes')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
SCHEME      = "Dilithium2"
VOTERS      = ["voter_001","voter_002","voter_003","voter_004","voter_005"]


def load_vote(voter_id):
    with open(os.path.join(VOTES_DIR, f"{voter_id}_vote.json")) as f:
        return json.load(f)

def load_pk(voter_id):
    with open(os.path.join(KEYS_DIR, f"{voter_id}_public.bin"), "rb") as f:
        return f.read()

def load_sk(voter_id):
    with open(os.path.join(KEYS_DIR, f"{voter_id}_secret.bin"), "rb") as f:
        return f.read()

def verify(payload_bytes, signature, pk):
    try:
        return bool(oqs.Signature(SCHEME).verify(payload_bytes, signature, pk))
    except Exception:
        return False

def sign(payload_bytes, sk):
    return oqs.Signature(SCHEME, sk).sign(payload_bytes)

def result_line(name, n_attempts, n_blocked, elapsed_ms):
    rate = n_attempts / max(elapsed_ms/1000, 0.0001)
    pct  = n_blocked / n_attempts * 100
    ok   = "OK" if n_blocked == n_attempts else "FAIL"
    print(f"  [{ok:<4}] {name:<40}  {n_blocked}/{n_attempts} blocked "
          f"({pct:.0f}%)  {elapsed_ms:.1f}ms  {rate:.0f}/s")
    return {"attack":name,"attempts":n_attempts,"blocked":n_blocked,
            "block_rate_pct":round(pct,1),"elapsed_ms":round(elapsed_ms,1),
            "rejection_rate":round(rate,1),"verdict":"HOLDS" if n_blocked==n_attempts else "FAILED"}


# ══════════════════════════════════════════════════════════════════════════════
# Attack 1: Replay — resubmit vote to different election
# ══════════════════════════════════════════════════════════════════════════════

def attack_replay():
    votes    = [load_vote(v) for v in VOTERS]
    blocked  = 0
    t0       = time.perf_counter()

    for vote in votes:
        # Replay: substitute a different election_id in the payload
        replayed_payload = dict(vote["payload"])
        replayed_payload["election_id"] = "ELECTION_2026_EG_FAKE"

        payload_bytes = json.dumps(replayed_payload, sort_keys=True).encode()
        signature     = bytes.fromhex(vote["signature"])
        pk            = load_pk(vote["payload"]["voter_id"])

        # Verification must fail — signature was over original election_id
        valid = verify(payload_bytes, signature, pk)
        if not valid:
            blocked += 1

    elapsed = (time.perf_counter()-t0)*1000
    return result_line("Replay (wrong election_id)", len(votes), blocked, elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# Attack 2: Vote flooding — 500 random payloads, no valid signature
# ══════════════════════════════════════════════════════════════════════════════

def attack_flood(n=500):
    pk      = load_pk("voter_001")
    blocked = 0
    t0      = time.perf_counter()

    for _ in range(n):
        # Random payload bytes
        payload_bytes = os.urandom(random.randint(50, 200))
        # Random signature of correct length (2420 bytes)
        fake_sig      = os.urandom(2420)
        valid = verify(payload_bytes, fake_sig, pk)
        if not valid:
            blocked += 1

    elapsed = (time.perf_counter()-t0)*1000
    return result_line("Vote flooding (random payloads)", n, blocked, elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# Attack 3: Signature stripping — valid payload, empty signature
# ══════════════════════════════════════════════════════════════════════════════

def attack_strip_signature():
    votes    = [load_vote(v) for v in VOTERS]
    blocked  = 0
    t0       = time.perf_counter()

    for vote in votes:
        payload_bytes = json.dumps(vote["payload"], sort_keys=True).encode()
        pk            = load_pk(vote["payload"]["voter_id"])
        # Try with empty signature, zero signature, and 1-byte signature
        for fake_sig in [b"", bytes(2420), bytes(1)]:
            valid = verify(payload_bytes, fake_sig, pk)
            if not valid:
                blocked += 1

    elapsed = (time.perf_counter()-t0)*1000
    return result_line("Signature stripping (empty/zero sig)", len(votes)*3, blocked, elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# Attack 4: Payload bit corruption
# ══════════════════════════════════════════════════════════════════════════════

def attack_bit_corruption():
    votes   = [load_vote(v) for v in VOTERS]
    blocked = 0
    total   = 0
    t0      = time.perf_counter()

    for vote in votes:
        payload_bytes = bytearray(
            json.dumps(vote["payload"], sort_keys=True).encode()
        )
        sig = bytes.fromhex(vote["signature"])
        pk  = load_pk(vote["payload"]["voter_id"])

        # Flip 1 bit at 5 different positions
        for pos in [0, 10, len(payload_bytes)//2, len(payload_bytes)-2, len(payload_bytes)-1]:
            corrupted        = bytearray(payload_bytes)
            corrupted[pos]  ^= 0x01
            valid = verify(bytes(corrupted), sig, pk)
            total += 1
            if not valid:
                blocked += 1

    elapsed = (time.perf_counter()-t0)*1000
    return result_line("Payload bit corruption (5 positions/vote)", total, blocked, elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# Attack 5: Cross-voter signature reuse
# ══════════════════════════════════════════════════════════════════════════════

def attack_cross_voter():
    """Use voter_001's signature with voter_002's payload and public key."""
    votes   = [load_vote(v) for v in VOTERS]
    blocked = 0
    total   = 0
    t0      = time.perf_counter()

    n = len(votes)
    for i in range(n):
        # Signature from voter i, payload + pk from voter (i+1)%n
        sig_vote     = votes[i]
        payload_vote = votes[(i+1) % n]

        sig           = bytes.fromhex(sig_vote["signature"])
        payload_bytes = json.dumps(payload_vote["payload"], sort_keys=True).encode()
        pk            = load_pk(payload_vote["payload"]["voter_id"])

        valid = verify(payload_bytes, sig, pk)
        total += 1
        if not valid:
            blocked += 1

    elapsed = (time.perf_counter()-t0)*1000
    return result_line("Cross-voter signature reuse", total, blocked, elapsed)


# ══════════════════════════════════════════════════════════════════════════════
# Bonus: Mass replay with valid signatures (timing attack attempt)
# ══════════════════════════════════════════════════════════════════════════════

def attack_timing_replay(n=200):
    """
    Submit the SAME valid vote repeatedly, hoping timing differences
    reveal information about the key. All should verify as True
    (signature IS valid for this payload) but the chain dedup layer
    would block them. Here we measure signature verification consistency.
    """
    vote          = load_vote("voter_001")
    pk            = load_pk("voter_001")
    payload_bytes = json.dumps(vote["payload"], sort_keys=True).encode()
    sig           = bytes.fromhex(vote["signature"])

    times   = []
    results = []
    t0      = time.perf_counter()
    for _ in range(n):
        tb    = time.perf_counter()
        valid = verify(payload_bytes, sig, pk)
        times.append((time.perf_counter()-tb)*1000)
        results.append(valid)

    elapsed = (time.perf_counter()-t0)*1000
    all_true = all(results)
    t_range  = max(times)-min(times)
    t_std    = (sum((t-sum(times)/len(times))**2 for t in times)/len(times))**0.5

    print(f"  [INFO] Timing replay ({n} runs):  "
          f"all_valid={all_true}  "
          f"time_range={t_range:.3f}ms  "
          f"stdev={t_std:.4f}ms  "
          f"(chain dedup blocks these at commit)")

    return {"attack":"Timing consistency (valid replay)",
            "n":n,"all_consistent":all_true,
            "time_range_ms":round(t_range,4),
            "time_stdev_ms":round(t_std,4),
            "note":"All verify True — chain dedup layer would block at commit"}


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*66}")
    print(f"  Security Attack Suite — {SCHEME}")
    print(f"{'='*66}\n")

    results = []

    print(f"  {'Attack':<44} {'Result':<22} {'Rate'}")
    print(f"  {'-'*66}")

    results.append(attack_replay())
    results.append(attack_flood(500))
    results.append(attack_strip_signature())
    results.append(attack_bit_corruption())
    results.append(attack_cross_voter())

    print()
    timing = attack_timing_replay(200)

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'='*66}")
    print(f"  ATTACK SUMMARY")
    print(f"{'='*66}")
    print(f"  {'Attack':<42} {'Blocked':>10}  {'Verdict'}")
    print(f"  {'-'*62}")
    for r in results:
        print(f"  {r['attack']:<42} "
              f"{r['blocked']}/{r['attempts']:>6}  "
              f"{r['verdict']}")

    total_attempts = sum(r["attempts"] for r in results)
    total_blocked  = sum(r["blocked"]  for r in results)
    overall_rate   = total_blocked/total_attempts*100

    print(f"\n  Total attacks    : {total_attempts}")
    print(f"  Total blocked    : {total_blocked}")
    print(f"  Overall block rate: {overall_rate:.1f}%")
    print(f"  System verdict   : {'HOLDS — all attacks blocked' if total_blocked==total_attempts else 'FAILED — some attacks succeeded'}")
    print(f"{'='*66}\n")

    report = {
        "scheme":          SCHEME,
        "total_attempts":  total_attempts,
        "total_blocked":   total_blocked,
        "overall_rate_pct":round(overall_rate,1),
        "attacks":         results,
        "timing_analysis": timing,
        "run_at":          datetime.now(timezone.utc).isoformat(),
    }
    out = os.path.join(RESULTS_DIR,"attack_suite_report.json")
    with open(out,"w") as f: json.dump(report,f,indent=2)
    print(f"  Report: {out}\n")

if __name__ == "__main__":
    main()
