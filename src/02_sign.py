import oqs
import os
import json
import time
import hashlib
from datetime import datetime

KEYS_DIR   = os.path.join(os.path.dirname(__file__), '..', 'keys')
VOTES_DIR  = os.path.join(os.path.dirname(__file__), '..', 'votes')
os.makedirs(VOTES_DIR, exist_ok=True)

SCHEME      = "Dilithium2"
ELECTION_ID = "ELECTION_2025_EG_001"

BALLOT = {
    "voter_001": "Candidate_A",
    "voter_002": "Candidate_B",
    "voter_003": "Candidate_A",
    "voter_004": "Candidate_C",
    "voter_005": "Candidate_B",
}

def load_secret_key(voter_id):
    path = os.path.join(KEYS_DIR, f"{voter_id}_secret.bin")
    with open(path, 'rb') as f:
        return f.read()

def build_payload(voter_id, choice):
    return {
        "election_id": ELECTION_ID,
        "voter_id":    voter_id,
        "choice":      choice,
        "timestamp":   datetime.utcnow().isoformat() + "Z"
    }

def sign_vote(voter_id, choice):
    secret_key    = load_secret_key(voter_id)
    signer        = oqs.Signature(SCHEME, secret_key)
    payload       = build_payload(voter_id, choice)
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    payload_hash  = hashlib.sha256(payload_bytes).hexdigest()

    t_start   = time.perf_counter()
    signature = signer.sign(payload_bytes)
    t_sign    = (time.perf_counter() - t_start) * 1000

    vote_record = {
        "payload":        payload,
        "payload_hash":   payload_hash,
        "signature":      signature.hex(),
        "signature_size": len(signature),
        "scheme":         SCHEME,
        "sign_time_ms":   round(t_sign, 4),
        "signed_at":      datetime.utcnow().isoformat() + "Z"
    }

    out_path = os.path.join(VOTES_DIR, f"{voter_id}_vote.json")
    with open(out_path, 'w') as f:
        json.dump(vote_record, f, indent=2)

    return vote_record, out_path

def main():
    print(f"\n{'='*58}")
    print(f"  Vote Signing -- {SCHEME}")
    print(f"  Election : {ELECTION_ID}")
    print(f"{'='*58}")

    all_times = []
    for voter_id, choice in BALLOT.items():
        record, path = sign_vote(voter_id, choice)
        all_times.append(record['sign_time_ms'])
        print(f"  [OK] {voter_id}  ->  {choice:<14}  "
              f"sig: {record['signature_size']} bytes  "
              f"time: {record['sign_time_ms']:.2f} ms")

    avg_time = sum(all_times) / len(all_times)
    print(f"\n  Total votes signed : {len(BALLOT)}")
    print(f"  Avg signing time   : {avg_time:.2f} ms")
    print(f"  Votes directory    : {os.path.abspath(VOTES_DIR)}")
    print(f"{'='*58}\n")

if __name__ == "__main__":
    main()
