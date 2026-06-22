"""
01_keygen.py — Dilithium2 (ML-DSA-44, NIST FIPS 204) key generation.

Generates one Dilithium2 key pair per voter and writes the public and secret keys
as raw bytes to ../keys/. The signing script (02_sign.py) loads these files by the
naming convention {voter_id}_secret.bin / {voter_id}_public.bin.

This script is part of the reproducibility artifacts for the paper
"Post-Quantum Blockchain for Secure Data Transmission: Design and Empirical
Evaluation Using CRYSTALS-Dilithium2".
"""
import os
import json
import oqs

SCHEME    = "Dilithium2"   # ML-DSA-44 in liboqs >= 0.10; FIPS 204
KEYS_DIR  = os.path.join(os.path.dirname(__file__), "..", "keys")
N_VOTERS  = 5              # five rotating key pairs, as used in the scale test


def generate_voter_keys(voter_id):
    """Generate and persist one Dilithium2 key pair for a voter."""
    signer     = oqs.Signature(SCHEME)
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()

    pub_path = os.path.join(KEYS_DIR, f"{voter_id}_public.bin")
    sec_path = os.path.join(KEYS_DIR, f"{voter_id}_secret.bin")
    with open(pub_path, "wb") as f:
        f.write(public_key)
    with open(sec_path, "wb") as f:
        f.write(secret_key)

    return {
        "voter_id":        voter_id,
        "public_bytes":    len(public_key),
        "secret_bytes":    len(secret_key),
        "public_key_file": os.path.basename(pub_path),
        "secret_key_file": os.path.basename(sec_path),
    }


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)
    summary = []
    print(f"  Phase 1 - Key generation ({SCHEME}) for {N_VOTERS} voters\n")
    for i in range(1, N_VOTERS + 1):
        voter_id = f"voter_{i:03d}"
        info = generate_voter_keys(voter_id)
        summary.append(info)
        print(f"    {voter_id}: public={info['public_bytes']} B, "
              f"secret={info['secret_bytes']} B")

    out = os.path.join(KEYS_DIR, "keygen_summary.json")
    with open(out, "w") as f:
        json.dump({"scheme": SCHEME, "n_voters": N_VOTERS, "keys": summary}, f, indent=2)
    print(f"\n  Summary written to {out}")


if __name__ == "__main__":
    main()
