import oqs
import os
import json
import time
import statistics

KEYS_DIR  = "/Users/lotfys/pqc_voting_project/keys"
VOTES_DIR = "/Users/lotfys/pqc_voting_project/votes"
SCHEME    = "Dilithium2"
RUNS      = 100   # 100 runs x 5 voters = 500 measurements each

VOTERS = ["voter_001", "voter_002", "voter_003", "voter_004", "voter_005"]

sign_times   = []
verify_times = []

print(f"\nRunning {RUNS} iterations per voter x {len(VOTERS)} voters = {RUNS*len(VOTERS)} total measurements...")
print("This will take about 10-15 seconds.\n")

for voter_id in VOTERS:
    with open(f"{KEYS_DIR}/{voter_id}_secret.bin", "rb") as f: sk = f.read()
    with open(f"{KEYS_DIR}/{voter_id}_public.bin", "rb") as f: pk = f.read()
    with open(f"{VOTES_DIR}/{voter_id}_vote.json") as f:
        record = json.load(f)

    payload_bytes = json.dumps(record["payload"], sort_keys=True).encode()
    signature     = bytes.fromhex(record["signature"])

    for _ in range(RUNS):
        signer = oqs.Signature(SCHEME, sk)
        t0 = time.perf_counter()
        signer.sign(payload_bytes)
        sign_times.append((time.perf_counter() - t0) * 1000)

    for _ in range(RUNS):
        verifier = oqs.Signature(SCHEME)
        t0 = time.perf_counter()
        verifier.verify(payload_bytes, signature, pk)
        verify_times.append((time.perf_counter() - t0) * 1000)

    print(f"  {voter_id} done.")

sign_times.sort()
verify_times.sort()

def p95(data): return data[int(len(data) * 0.95)]
def p99(data): return data[int(len(data) * 0.99)]

print(f"\n{'='*65}")
print(f"  Benchmark Results — {SCHEME}  ({RUNS*len(VOTERS)} runs per metric)")
print(f"{'='*65}")
print(f"  SIGNING")
print(f"    avg    : {statistics.mean(sign_times):.4f} ms")
print(f"    median : {statistics.median(sign_times):.4f} ms")
print(f"    p95    : {p95(sign_times):.4f} ms")
print(f"    p99    : {p99(sign_times):.4f} ms")
print(f"    min    : {min(sign_times):.4f} ms")
print(f"    max    : {max(sign_times):.4f} ms")
print(f"    stdev  : {statistics.stdev(sign_times):.4f} ms")
print(f"\n  VERIFICATION")
print(f"    avg    : {statistics.mean(verify_times):.4f} ms")
print(f"    median : {statistics.median(verify_times):.4f} ms")
print(f"    p95    : {p95(verify_times):.4f} ms")
print(f"    p99    : {p99(verify_times):.4f} ms")
print(f"    min    : {min(verify_times):.4f} ms")
print(f"    max    : {max(verify_times):.4f} ms")
print(f"    stdev  : {statistics.stdev(verify_times):.4f} ms")
print(f"{'='*65}\n")
