"""
08_storage.py — Storage Overhead Analysis
==========================================
Measures storage cost at every level of the system:
  - Per-field vote record breakdown
  - Per-block overhead
  - Chain growth rate and projection to 67M votes
  - Comparison with RSA-2048 and ECDSA-256
"""

import os, json, time
from datetime import datetime, timezone

KEYS_DIR    = os.path.join(os.path.dirname(__file__), '..', 'keys')
VOTES_DIR   = os.path.join(os.path.dirname(__file__), '..', 'votes')
CHAIN_DIR   = os.path.join(os.path.dirname(__file__), '..', 'chain')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
SCHEME      = "Dilithium2"

def human(n):
    if n >= 1_073_741_824: return f"{n/1_073_741_824:.2f} GB"
    if n >= 1_048_576:     return f"{n/1_048_576:.2f} MB"
    if n >= 1_024:         return f"{n/1_024:.2f} KB"
    return f"{n} B"

def measure_vote(path):
    with open(path) as f: r = json.load(f)
    raw   = json.dumps(r, indent=2).encode()
    pay   = json.dumps(r["payload"], sort_keys=True).encode()
    phash = r["payload_hash"].encode()
    sig   = bytes.fromhex(r["signature"])
    meta  = json.dumps({"signature_size":r["signature_size"],"sign_time_ms":r["sign_time_ms"]}).encode()
    return {"total":len(raw),"payload":len(pay),"signature":len(sig),
            "hash":len(phash),"metadata":len(meta),
            "sig_pct":round(len(sig)/len(raw)*100,1)}

def measure_block(b):
    bj = json.dumps(b, indent=2).encode()
    hj = json.dumps({"index":b["index"],"timestamp":b["timestamp"],
                     "merkle_root":b["merkle_root"],"previous_hash":b["previous_hash"],
                     "block_hash":b["block_hash"]}).encode()
    vj = json.dumps(b.get("votes",[])).encode()
    vc = b.get("vote_count", len(b.get("votes",[])))
    return {"total":len(bj),"header":len(hj),"votes_data":len(vj),
            "vote_count":vc,"bytes_per_vote":round(len(vj)/max(1,vc),1)}

def main():
    print(f"\n{'='*62}")
    print(f"  Storage Overhead Analysis — {SCHEME}")
    print(f"{'='*62}")

    # ── 1. Vote record ────────────────────────────────────────────────────
    print(f"\n  [ 1. Per-vote field breakdown ]\n")
    vms = []
    for vid in ["voter_001","voter_002","voter_003","voter_004","voter_005"]:
        m = measure_vote(os.path.join(VOTES_DIR, f"{vid}_vote.json"))
        vms.append(m)
        print(f"  {vid}  total:{m['total']}B  payload:{m['payload']}B  "
              f"sig:{m['signature']}B  hash:{m['hash']}B  sig_overhead:{m['sig_pct']}%")

    avgt = sum(m["total"]     for m in vms)/5
    avgp = sum(m["payload"]   for m in vms)/5
    avgs = sum(m["signature"] for m in vms)/5
    avgh = sum(m["hash"]      for m in vms)/5
    avgm = sum(m["metadata"]  for m in vms)/5

    print(f"\n  Average vote record : {avgt:.0f} bytes")
    print(f"    Payload           : {avgp:.0f}B  ({avgp/avgt*100:.1f}%)")
    print(f"    Signature         : {avgs:.0f}B  ({avgs/avgt*100:.1f}%)")
    print(f"    Payload hash      : {avgh:.0f}B  ({avgh/avgt*100:.1f}%)")
    print(f"    Metadata          : {avgm:.0f}B  ({avgm/avgt*100:.1f}%)")

    # ── 2. Block breakdown ────────────────────────────────────────────────
    print(f"\n  [ 2. Block-level breakdown ]\n")
    chain = json.load(open(os.path.join(CHAIN_DIR,"voting_chain.json")))
    bms   = [measure_block(b) for b in chain["blocks"][1:]]
    for i,bm in enumerate(bms,1):
        print(f"  Block #{i}  total:{bm['total']}B  header:{bm['header']}B  "
              f"votes_data:{bm['votes_data']}B  votes:{bm['vote_count']}  "
              f"bytes/vote:{bm['bytes_per_vote']}B")

    avg_bt  = sum(m["total"]         for m in bms)/len(bms)
    avg_bh  = sum(m["header"]        for m in bms)/len(bms)
    avg_bpv = sum(m["bytes_per_vote"]for m in bms)/len(bms)
    print(f"\n  Avg block size      : {avg_bt:.0f}B")
    print(f"  Avg header overhead : {avg_bh:.0f}B")
    print(f"  Avg bytes per vote  : {avg_bpv:.0f}B")

    # ── 3. Chain on disk ──────────────────────────────────────────────────
    print(f"\n  [ 3. Chain file (on disk) ]\n")
    disk  = os.path.getsize(os.path.join(CHAIN_DIR,"voting_chain.json"))
    tv    = sum(b.get("vote_count",len(b.get("votes",[]))) for b in chain["blocks"][1:])
    print(f"  Chain file size : {human(disk)} ({disk} bytes)")
    print(f"  Total votes     : {tv}")
    print(f"  Bytes per vote  : {disk//max(1,tv)} bytes")

    # ── 4. Projections ────────────────────────────────────────────────────
    bpv = avgt  # use avg record size for projection
    print(f"\n  [ 4. Storage projection @ {bpv:.0f} bytes/vote ]\n")
    scales = [("1,000 votes",1_000),("10,000 votes",10_000),
              ("100,000 votes",100_000),("1M votes",1_000_000),
              ("10M votes",10_000_000),("67M (Egypt)",67_000_000)]
    print(f"  {'Scale':<20} {'Votes':>12}  {'Storage'}")
    print(f"  {'-'*46}")
    proj_data = {}
    for label,n in scales:
        total = int(n*bpv)
        proj_data[label] = {"votes":n,"bytes":total,"human":human(total)}
        print(f"  {label:<20} {n:>12,}  {human(total)}")

    # ── 5. Scheme comparison ──────────────────────────────────────────────
    print(f"\n  [ 5. Scheme comparison @ 1M votes ]\n")
    schemes = {
        "Dilithium2": {"public_key":1312,"signature":2420,"record":int(avgt)},
        "RSA-2048":   {"public_key":294, "signature":256, "record":1000},
        "ECDSA-256":  {"public_key":64,  "signature":72,  "record":400},
    }
    print(f"  {'Scheme':<14} {'PubKey':>8}  {'Sig':>8}  {'Record':>8}  {'1M storage':>14}  {'vs ECDSA'}")
    print(f"  {'-'*68}")
    ecdsa_rec = schemes["ECDSA-256"]["record"]
    for name,v in schemes.items():
        total_1m = v["record"]*1_000_000
        ratio    = round(v["record"]/ecdsa_rec,1)
        print(f"  {name:<14} {v['public_key']:>6}B  {v['signature']:>6}B  "
              f"{v['record']:>6}B  {human(total_1m):>14}  {ratio}x")

    print(f"\n{'='*62}\n")

    report = {"scheme":SCHEME,"avg_record_bytes":round(avgt,1),
              "field_breakdown":{"payload":round(avgp,1),"signature":round(avgs,1),
                                 "hash":round(avgh,1),"metadata":round(avgm,1),
                                 "sig_pct":round(avgs/avgt*100,1)},
              "block_stats":{"avg_total":round(avg_bt,1),"avg_header":round(avg_bh,1),
                             "avg_bytes_per_vote":round(avg_bpv,1)},
              "chain_on_disk_bytes":disk,"chain_votes":tv,
              "projections":proj_data,"scheme_comparison":schemes,
              "run_at":datetime.now(timezone.utc).isoformat()}
    out = os.path.join(RESULTS_DIR,"storage_report.json")
    with open(out,"w") as f: json.dump(report,f,indent=2)
    print(f"  Report: {out}\n")

if __name__ == "__main__":
    main()
