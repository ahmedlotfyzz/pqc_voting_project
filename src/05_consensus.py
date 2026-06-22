"""
05_consensus.py — Q-PnV Inspired Consensus Mechanism
=====================================================
Implements a simplified Q-PnV (Quantum Proof-and-Vote) consensus
protocol for the voting blockchain.

How it works:
  1. A proposer node proposes a block (hash + metadata)
  2. Each validator independently verifies the block's Merkle root
  3. Each validator signs a consensus message with its Dilithium2 key
  4. Signed votes are collected and weighted by validator stake
  5. If weighted approval >= THRESHOLD the block is FINALISED

Consensus parameters:
  - 3 validator nodes
  - Weighted stakes: [50%, 30%, 20%]
  - Approval threshold: 67% weighted stake
"""

import oqs
import os
import json
import hashlib
import time
from datetime import datetime, timezone

KEYS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'keys')
CHAIN_DIR   = os.path.join(os.path.dirname(__file__), '..', 'chain')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

SCHEME    = "Dilithium2"
THRESHOLD = 0.67


# ══════════════════════════════════════════════════════════════════════════════
# Validator Node
# ══════════════════════════════════════════════════════════════════════════════

class ValidatorNode:
    def __init__(self, node_id: str, stake: float, force_decision: str = None):
        """
        force_decision: None = honest, "APPROVE" = always approve,
                        "REJECT" = always reject
        """
        self.node_id        = node_id
        self.stake          = stake
        self.force_decision = force_decision

        signer          = oqs.Signature(SCHEME)
        self.public_key = signer.generate_keypair()
        self.secret_key = signer.export_secret_key()

    def _check_merkle(self, block_dict: dict) -> bool:
        vote_hashes = [v["payload_hash"] for v in block_dict.get("votes", [])]
        if not vote_hashes:
            return True
        layer = [bytes.fromhex(h) for h in vote_hashes]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            layer = [
                hashlib.sha256(layer[i] + layer[i+1]).digest()
                for i in range(0, len(layer), 2)
            ]
        return layer[0].hex() == block_dict.get("merkle_root", "")

    def cast_vote(self, block_hash: str, block_index: int,
                  block_dict: dict) -> dict:
        t_start   = time.perf_counter()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Determine decision
        if self.force_decision:
            decision = self.force_decision
        else:
            decision = "APPROVE" if self._check_merkle(block_dict) else "REJECT"

        # Build message — exact same dict used for signing AND verification
        msg_dict = {
            "node_id":     self.node_id,
            "block_index": block_index,
            "block_hash":  block_hash,
            "decision":    decision,
            "timestamp":   timestamp,
        }
        msg_bytes = json.dumps(msg_dict, sort_keys=True).encode("utf-8")

        signer    = oqs.Signature(SCHEME, self.secret_key)
        signature = signer.sign(msg_bytes)
        elapsed   = (time.perf_counter() - t_start) * 1000

        return {
            "node_id":     self.node_id,
            "stake":       self.stake,
            "forced":      self.force_decision,
            "block_index": block_index,
            "block_hash":  block_hash,
            "decision":    decision,
            "approved":    decision == "APPROVE",
            "timestamp":   timestamp,
            "signature":   signature.hex(),
            "sig_size":    len(signature),
            "public_key":  self.public_key.hex(),
            "sign_ms":     round(elapsed, 4),
        }


# ══════════════════════════════════════════════════════════════════════════════
# Consensus Engine
# ══════════════════════════════════════════════════════════════════════════════

class ConsensusEngine:
    def __init__(self, validators: list, threshold: float):
        self.validators = validators
        self.threshold  = threshold

    def _verify_validator_sig(self, vote: dict) -> bool:
        msg_dict = {
            "node_id":     vote["node_id"],
            "block_index": vote["block_index"],
            "block_hash":  vote["block_hash"],
            "decision":    vote["decision"],
            "timestamp":   vote["timestamp"],
        }
        msg_bytes = json.dumps(msg_dict, sort_keys=True).encode("utf-8")
        try:
            pk  = bytes.fromhex(vote["public_key"])
            sig = bytes.fromhex(vote["signature"])
            return bool(oqs.Signature(SCHEME).verify(msg_bytes, sig, pk))
        except Exception:
            return False

    def run(self, block_dict: dict, label: str = "") -> dict:
        t_start     = time.perf_counter()
        block_hash  = block_dict["block_hash"]
        block_index = block_dict["index"]

        print(f"\n  Proposing block #{block_index}  "
              f"hash={block_hash[:24]}...")
        print(f"  Validators: {len(self.validators)}  "
              f"Threshold: {self.threshold*100:.0f}% weighted stake\n")

        validator_votes  = []
        weighted_approve = 0.0
        weighted_total   = 0.0

        for v in self.validators:
            vote   = v.cast_vote(block_hash, block_index, block_dict)
            sig_ok = self._verify_validator_sig(vote)
            vote["sig_verified"] = sig_ok
            validator_votes.append(vote)
            weighted_total += v.stake
            if vote["approved"]:
                weighted_approve += v.stake

            tag = ""
            if v.force_decision == "APPROVE":
                tag = " [BYZANTINE — forced APPROVE]"
            elif v.force_decision == "REJECT":
                tag = " [FAULTY — forced REJECT]"
            sig_tag = "sig:OK  " if sig_ok else "sig:FAIL"
            print(f"  [{vote['decision']:<7}]  {v.node_id:<14}  "
                  f"stake={v.stake*100:.0f}%  {sig_tag}  "
                  f"sign:{vote['sign_ms']:.2f}ms{tag}")

        approval_ratio = weighted_approve / weighted_total if weighted_total else 0
        finalised      = approval_ratio >= self.threshold
        elapsed        = (time.perf_counter() - t_start) * 1000

        return {
            "label":           label,
            "block_index":     block_index,
            "block_hash":      block_hash,
            "validator_votes": validator_votes,
            "weighted_approve": round(weighted_approve, 4),
            "approval_ratio":   round(approval_ratio,   4),
            "threshold":        self.threshold,
            "finalised":        finalised,
            "consensus_ms":     round(elapsed, 4),
            "verdict":          "FINALISED" if finalised else "REJECTED",
        }


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def load_chain() -> dict:
    with open(os.path.join(CHAIN_DIR, "voting_chain.json")) as f:
        return json.load(f)

def main():
    print(f"\n{'='*62}")
    print(f"  Q-PnV Consensus — {SCHEME} validator signatures")
    print(f"{'='*62}")

    print(f"\n  [ Generating validator key pairs ]\n")
    base_validators = [
        ValidatorNode("validator_A", stake=0.50),
        ValidatorNode("validator_B", stake=0.30),
        ValidatorNode("validator_C", stake=0.20),
    ]
    for v in base_validators:
        print(f"  {v.node_id}  stake={v.stake*100:.0f}%  "
              f"pk={v.public_key.hex()[:20]}...")

    chain = load_chain()
    all_results = {
        "scheme": SCHEME, "threshold": THRESHOLD,
        "run_at": datetime.now(timezone.utc).isoformat(), "rounds": []
    }

    # Round 1 — block #1, all honest
    print(f"\n{'─'*62}")
    print(f"  [ Round 1 — Block #1, all validators honest ]")
    r1 = ConsensusEngine(base_validators, THRESHOLD).run(
        chain["blocks"][1], "block1_honest")
    print(f"\n  Approval: {r1['approval_ratio']*100:.1f}%  -> {r1['verdict']}")
    all_results["rounds"].append(r1)

    # Round 2 — block #2, all honest
    print(f"\n{'─'*62}")
    print(f"  [ Round 2 — Block #2, all validators honest ]")
    r2 = ConsensusEngine(base_validators, THRESHOLD).run(
        chain["blocks"][2], "block2_honest")
    print(f"\n  Approval: {r2['approval_ratio']*100:.1f}%  -> {r2['verdict']}")
    all_results["rounds"].append(r2)

    # Round 3 — 1 faulty validator (always rejects)
    print(f"\n{'─'*62}")
    print(f"  [ Round 3 — Byzantine fault: validator_C always rejects ]")
    v3 = [
        ValidatorNode("validator_A", stake=0.50),
        ValidatorNode("validator_B", stake=0.30),
        ValidatorNode("validator_C", stake=0.20, force_decision="REJECT"),
    ]
    r3 = ConsensusEngine(v3, THRESHOLD).run(
        chain["blocks"][1], "block1_byz_f1")
    print(f"\n  Approval: {r3['approval_ratio']*100:.1f}%  -> {r3['verdict']}")
    print(f"  Honest majority (80%) overrides 1 faulty node (20%)")
    all_results["rounds"].append(r3)

    # Round 4 — majority byzantine (always approves anything)
    print(f"\n{'─'*62}")
    print(f"  [ Round 4 — Attack: 80% stake forces APPROVE ]")
    v4 = [
        ValidatorNode("validator_A", stake=0.50, force_decision="APPROVE"),
        ValidatorNode("validator_B", stake=0.30, force_decision="APPROVE"),
        ValidatorNode("validator_C", stake=0.20),
    ]
    r4 = ConsensusEngine(v4, THRESHOLD).run(
        chain["blocks"][1], "block1_majority_byz")
    print(f"\n  Approval: {r4['approval_ratio']*100:.1f}%  -> {r4['verdict']}")
    print(f"  Confirms: >67% byzantine stake breaks safety — "
          f"honest majority is required.")
    all_results["rounds"].append(r4)

    # Summary
    print(f"\n{'='*62}")
    print(f"  CONSENSUS SUMMARY")
    print(f"{'='*62}")
    rows = [
        ("Block #1 — all honest",           r1),
        ("Block #2 — all honest",           r2),
        ("Block #1 — 1 faulty (20% stake)", r3),
        ("Block #1 — 80% byzantine",        r4),
    ]
    print(f"  {'Scenario':<38} {'Approval':>9}  Verdict")
    print(f"  {'-'*62}")
    for label, r in rows:
        print(f"  {label:<38} {r['approval_ratio']*100:>8.1f}%  {r['verdict']}")

    all_sigs = [vv["sig_size"] for r in [r1,r2] for vv in r["validator_votes"]]
    print(f"\n  Validator sig size (avg) : {sum(all_sigs)//len(all_sigs)} bytes  (Dilithium2)")
    print(f"  Consensus round (avg)    : "
          f"{sum(r['consensus_ms'] for r in [r1,r2,r3,r4])/4:.2f} ms")
    print(f"{'='*62}\n")

    out = os.path.join(RESULTS_DIR, "consensus_report.json")
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"  Report: {out}\n")


if __name__ == "__main__":
    main()
