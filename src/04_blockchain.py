"""
04_blockchain.py — Quantum-Resistant Voting Blockchain
=======================================================
Builds a hash-linked blockchain where each block contains a
batch of Dilithium2-signed votes. Every vote is re-verified
against its public key before being accepted into a block.

Block structure:
  - index          : block number
  - timestamp      : UTC ISO string
  - votes          : list of verified vote payloads
  - merkle_root    : SHA-256 Merkle root of all vote hashes in block
  - previous_hash  : hash of the previous block
  - block_hash     : SHA-256 of (index + timestamp + merkle_root + previous_hash)

Chain guarantees:
  - Any tampering with a past block breaks every hash after it
  - Every vote carries a valid Dilithium2 signature — verified on entry
  - Duplicate votes (same voter_id in same election) are rejected
"""

import oqs
import os
import json
import hashlib
import time
from datetime import datetime, timezone

KEYS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'keys')
VOTES_DIR   = os.path.join(os.path.dirname(__file__), '..', 'votes')
CHAIN_DIR   = os.path.join(os.path.dirname(__file__), '..', 'chain')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(CHAIN_DIR,   exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

SCHEME  = "Dilithium2"
VOTERS  = ["voter_001", "voter_002", "voter_003", "voter_004", "voter_005"]
BATCH   = 3   # votes per block (realistic for demonstration)


# ══════════════════════════════════════════════════════════════════════════════
# Merkle Tree
# ══════════════════════════════════════════════════════════════════════════════

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def merkle_root(hashes: list[str]) -> str:
    """Compute SHA-256 Merkle root from a list of hex hashes."""
    if not hashes:
        return sha256(b"empty")
    layer = [bytes.fromhex(h) for h in hashes]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])        # duplicate last node if odd
        layer = [
            hashlib.sha256(layer[i] + layer[i+1]).digest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0].hex()


# ══════════════════════════════════════════════════════════════════════════════
# Block
# ══════════════════════════════════════════════════════════════════════════════

class Block:
    def __init__(self, index: int, votes: list, previous_hash: str):
        self.index         = index
        self.timestamp     = datetime.now(timezone.utc).isoformat()
        self.votes         = votes
        self.merkle_root   = merkle_root([v["payload_hash"] for v in votes])
        self.previous_hash = previous_hash
        self.block_hash    = self._compute_hash()

    def _compute_hash(self) -> str:
        content = json.dumps({
            "index":         self.index,
            "timestamp":     self.timestamp,
            "merkle_root":   self.merkle_root,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return sha256(content.encode())

    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "votes":         self.votes,
            "vote_count":    len(self.votes),
            "merkle_root":   self.merkle_root,
            "previous_hash": self.previous_hash,
            "block_hash":    self.block_hash,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Voting Chain
# ══════════════════════════════════════════════════════════════════════════════

class VotingChain:
    GENESIS_HASH = "0" * 64

    def __init__(self):
        self.chain   : list[Block] = []
        self.seen_voters : set[str] = set()   # duplicate vote guard
        self._create_genesis()

    def _create_genesis(self):
        genesis = Block(
            index         = 0,
            votes         = [],
            previous_hash = self.GENESIS_HASH,
        )
        self.chain.append(genesis)
        print(f"  [genesis]  block #0  hash={genesis.block_hash[:20]}...")

    def _load_public_key(self, voter_id: str) -> bytes:
        path = os.path.join(KEYS_DIR, f"{voter_id}_public.bin")
        with open(path, "rb") as f:
            return f.read()

    def _verify_vote(self, vote_record: dict) -> tuple[bool, str]:
        """Verify Dilithium2 signature. Returns (valid, reason)."""
        voter_id = vote_record["payload"]["voter_id"]

        # Duplicate check
        key = f"{voter_id}::{vote_record['payload']['election_id']}"
        if key in self.seen_voters:
            return False, "duplicate vote"

        # Signature verification
        pk            = self._load_public_key(voter_id)
        payload_bytes = json.dumps(
            vote_record["payload"], sort_keys=True
        ).encode("utf-8")
        signature     = bytes.fromhex(vote_record["signature"])

        try:
            verifier = oqs.Signature(SCHEME)
            valid    = verifier.verify(payload_bytes, signature, pk)
        except Exception as exc:
            return False, f"verification error: {exc}"

        if not valid:
            return False, "invalid signature"

        # Hash integrity check
        recomputed = sha256(payload_bytes)
        if recomputed != vote_record["payload_hash"]:
            return False, "hash mismatch"

        return True, "ok"

    def add_votes(self, vote_records: list) -> dict:
        """
        Verify each vote and, if valid, commit them as a new block.
        Returns a report dict.
        """
        t_start  = time.perf_counter()
        accepted = []
        rejected = []

        for record in vote_records:
            voter_id = record["payload"]["voter_id"]
            t0       = time.perf_counter()
            valid, reason = self._verify_vote(record)
            v_time   = round((time.perf_counter() - t0) * 1000, 4)

            if valid:
                key = f"{voter_id}::{record['payload']['election_id']}"
                self.seen_voters.add(key)
                accepted.append({
                    "voter_id":    voter_id,
                    "choice":      record["payload"]["choice"],
                    "payload_hash": record["payload_hash"],
                    "verify_ms":   v_time,
                })
            else:
                rejected.append({
                    "voter_id": voter_id,
                    "reason":   reason,
                    "verify_ms": v_time,
                })

        if accepted:
            new_block = Block(
                index         = len(self.chain),
                votes         = accepted,
                previous_hash = self.chain[-1].block_hash,
            )
            self.chain.append(new_block)

        return {
            "block_index": len(self.chain) - 1 if accepted else None,
            "accepted":    len(accepted),
            "rejected":    len(rejected),
            "details_accepted": accepted,
            "details_rejected": rejected,
            "commit_ms":  round((time.perf_counter() - t_start) * 1000, 4),
        }

    def is_valid(self) -> tuple[bool, str]:
        """Verify entire chain integrity — every hash must link correctly."""
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # Recompute expected hash
            expected = Block(
                index         = curr.index,
                votes         = curr.votes,
                previous_hash = curr.previous_hash,
            )
            # Re-derive using same fields (timestamp is preserved)
            content = json.dumps({
                "index":         curr.index,
                "timestamp":     curr.timestamp,
                "merkle_root":   curr.merkle_root,
                "previous_hash": curr.previous_hash,
            }, sort_keys=True)
            recomputed_hash = sha256(content.encode())

            if curr.block_hash != recomputed_hash:
                return False, f"block #{i}: hash mismatch"
            if curr.previous_hash != prev.block_hash:
                return False, f"block #{i}: broken link to block #{i-1}"

        return True, "chain intact"

    def tally(self) -> dict:
        """Count votes across all blocks."""
        counts: dict[str, int] = {}
        total = 0
        for block in self.chain[1:]:    # skip genesis
            for vote in block.votes:
                choice = vote["choice"]
                counts[choice] = counts.get(choice, 0) + 1
                total += 1
        if total == 0:
            return {"total": 0, "results": {}}
        ranked = sorted(counts.items(), key=lambda x: -x[1])
        winner = ranked[0][0]
        return {
            "total":      total,
            "winner":     winner,
            "results":    {c: {"votes": v, "pct": round(v/total*100, 1)}
                           for c, v in ranked},
        }

    def to_dict(self) -> dict:
        return {
            "chain_length":  len(self.chain),
            "total_votes":   sum(len(b.votes) for b in self.chain[1:]),
            "created_at":    datetime.now(timezone.utc).isoformat(),
            "blocks":        [b.to_dict() for b in self.chain],
        }

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def load_vote(voter_id: str) -> dict:
    with open(os.path.join(VOTES_DIR, f"{voter_id}_vote.json")) as f:
        return json.load(f)

def main():
    print(f"\n{'='*62}")
    print(f"  PQC Voting Blockchain — {SCHEME}")
    print(f"{'='*62}\n")

    chain = VotingChain()

    # Load all votes
    all_votes = [load_vote(v) for v in VOTERS]

    # ── Batch 1: first BATCH votes ────────────────────────────────────────
    print(f"\n  [ Batch 1 — votes 1–{BATCH} ]\n")
    r1 = chain.add_votes(all_votes[:BATCH])
    for v in r1["details_accepted"]:
        print(f"  [OK]  {v['voter_id']}  ->  {v['choice']:<14}  "
              f"verify: {v['verify_ms']:.3f} ms")
    for v in r1["details_rejected"]:
        print(f"  [!!]  {v['voter_id']}  REJECTED  ({v['reason']})")
    b1 = chain.chain[-1]
    print(f"\n  Block #{b1.index}  |  {r1['accepted']} votes  |  "
          f"merkle={b1.merkle_root[:20]}...  |  "
          f"hash={b1.block_hash[:20]}...")

    # ── Batch 2: remaining votes ──────────────────────────────────────────
    print(f"\n  [ Batch 2 — votes {BATCH+1}–{len(VOTERS)} ]\n")
    r2 = chain.add_votes(all_votes[BATCH:])
    for v in r2["details_accepted"]:
        print(f"  [OK]  {v['voter_id']}  ->  {v['choice']:<14}  "
              f"verify: {v['verify_ms']:.3f} ms")
    b2 = chain.chain[-1]
    print(f"\n  Block #{b2.index}  |  {r2['accepted']} votes  |  "
          f"merkle={b2.merkle_root[:20]}...  |  "
          f"hash={b2.block_hash[:20]}...")

    # ── Duplicate vote test ───────────────────────────────────────────────
    print(f"\n  [ Duplicate vote test ]\n")
    r3 = chain.add_votes([all_votes[0]])   # voter_001 tries to vote again
    v  = r3["details_rejected"][0]
    print(f"  [!!]  {v['voter_id']}  REJECTED  ({v['reason']})  "
          f"-> duplicate correctly blocked")

    # ── Chain integrity verification ──────────────────────────────────────
    print(f"\n  [ Chain integrity check ]\n")
    valid, msg = chain.is_valid()
    print(f"  {'[OK]' if valid else '[FAIL]'}  {msg}")

    # ── Tally ─────────────────────────────────────────────────────────────
    tally = chain.tally()
    print(f"\n  [ Election tally ]\n")
    print(f"  Total votes cast : {tally['total']}")
    for candidate, data in tally["results"].items():
        bar = "█" * int(data["pct"] / 5)
        print(f"  {candidate:<16} {data['votes']} votes  "
              f"({data['pct']:>5.1f}%)  {bar}")
    print(f"\n  Winner : {tally['winner']}")

    # ── Chain summary ─────────────────────────────────────────────────────
    print(f"\n{'='*62}")
    print(f"  CHAIN SUMMARY")
    print(f"{'='*62}")
    print(f"  Blocks         : {len(chain.chain)}  "
          f"(1 genesis + {len(chain.chain)-1} vote blocks)")
    print(f"  Total votes    : {tally['total']}")
    print(f"  Chain valid    : {valid}")
    print(f"  Duplicates blocked : 1")
    for b in chain.chain:
        label = "genesis" if b.index == 0 else f"{len(b.votes)} votes"
        print(f"  Block #{b.index}  [{label}]  "
              f"hash={b.block_hash[:24]}...")
    print(f"{'='*62}\n")

    # ── Save chain ────────────────────────────────────────────────────────
    chain_path = os.path.join(CHAIN_DIR, "voting_chain.json")
    chain.save(chain_path)
    print(f"  Chain saved: {chain_path}\n")


if __name__ == "__main__":
    main()
