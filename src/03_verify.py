import oqs
import os
import json
import time
import hashlib
from datetime import datetime

KEYS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'keys')
VOTES_DIR   = os.path.join(os.path.dirname(__file__), '..', 'votes')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

SCHEME = "Dilithium2"
VOTERS = ["voter_001", "voter_002", "voter_003", "voter_004", "voter_005"]


def load_public_key(voter_id):
    path = os.path.join(KEYS_DIR, f"{voter_id}_public.bin")
    with open(path, 'rb') as f:
        return f.read()


def load_vote(voter_id):
    path = os.path.join(VOTES_DIR, f"{voter_id}_vote.json")
    with open(path, 'r') as f:
        return json.load(f)


def verify_vote(voter_id, vote_record, tamper=False):
    public_key    = load_public_key(voter_id)
    verifier      = oqs.Signature(SCHEME)

    payload       = vote_record['payload']
    signature     = bytes.fromhex(vote_record['signature'])

    # Optionally tamper with the payload before verifying
    if tamper:
        payload = dict(payload)
        payload['choice'] = "Candidate_TAMPERED"

    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')

    t_start = time.perf_counter()
    try:
        valid = verifier.verify(payload_bytes, signature, public_key)
    except Exception:
        valid = False
    t_verify = (time.perf_counter() - t_start) * 1000

    # Recompute hash to detect any drift
    recomputed_hash = hashlib.sha256(payload_bytes).hexdigest()
    hash_match      = (recomputed_hash == vote_record['payload_hash']) and not tamper

    return {
        "voter_id":        voter_id,
        "choice":          vote_record['payload']['choice'],
        "tampered":        tamper,
        "signature_valid": bool(valid),
        "hash_match":      hash_match,
        "verify_time_ms":  round(t_verify, 4),
        "signature_size":  vote_record['signature_size'],
        "verified_at":     datetime.utcnow().isoformat() + "Z"
    }


def print_result(r):
    status = "PASS" if r['signature_valid'] and not r['tampered'] else \
             "BLOCKED" if r['tampered'] and not r['signature_valid'] else "FAIL"
    icon   = "[OK]" if status == "PASS" else "[!!]" if status == "BLOCKED" else "[XX]"
    label  = "tampered" if r['tampered'] else "genuine "
    print(f"  {icon} {r['voter_id']}  [{label}]  valid={r['signature_valid']}  "
          f"hash_ok={r['hash_match']}  time={r['verify_time_ms']:.3f} ms  -> {status}")


def main():
    print(f"\n{'='*64}")
    print(f"  Vote Verification + Tamper Detection — {SCHEME}")
    print(f"{'='*64}")

    all_results  = []
    verify_times = []

    # --- Part 1: Verify all genuine votes ---
    print(f"\n  [ Genuine votes ]\n")
    for voter_id in VOTERS:
        vote   = load_vote(voter_id)
        result = verify_vote(voter_id, vote, tamper=False)
        all_results.append(result)
        verify_times.append(result['verify_time_ms'])
        print_result(result)

    # --- Part 2: Tamper attack simulation ---
    print(f"\n  [ Tamper attack simulation ]\n")
    for voter_id in VOTERS[:3]:   # attack first 3 voters
        vote   = load_vote(voter_id)
        result = verify_vote(voter_id, vote, tamper=True)
        all_results.append(result)
        print_result(result)

    # --- Summary ---
    genuine   = [r for r in all_results if not r['tampered']]
    tampered  = [r for r in all_results if r['tampered']]
    passed    = sum(1 for r in genuine  if r['signature_valid'])
    blocked   = sum(1 for r in tampered if not r['signature_valid'])
    avg_vtime = sum(verify_times) / len(verify_times)

    print(f"\n{'='*64}")
    print(f"  Genuine votes   : {len(genuine)}  |  verified OK : {passed}/{len(genuine)}")
    print(f"  Tamper attempts : {len(tampered)}  |  blocked     : {blocked}/{len(tampered)}")
    print(f"  Avg verify time : {avg_vtime:.3f} ms")
    print(f"{'='*64}\n")

    # --- Save report ---
    report = {
        "scheme":            SCHEME,
        "run_at":            datetime.utcnow().isoformat() + "Z",
        "genuine_votes":     len(genuine),
        "verified_ok":       passed,
        "tamper_attempts":   len(tampered),
        "tamper_blocked":    blocked,
        "avg_verify_time_ms": round(avg_vtime, 4),
        "details":           all_results
    }
    report_path = os.path.join(RESULTS_DIR, 'verification_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"  Report saved to: {report_path}\n")


if __name__ == "__main__":
    main()
