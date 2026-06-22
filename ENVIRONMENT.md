# Environment and reproducibility details

This file documents the exact hardware and software environment used to produce the
results in the manuscript, as requested by the editor for full reproducibility.

## Hardware

| Component | Specification |
|---|---|
| Machine   | MacBook Pro (2015) |
| CPU       | Intel Core i7 |
| RAM       | 16 GB DDR3 |
| Storage   | 1 TB SSD |
| OS        | macOS |

The evaluation is a **controlled single-machine prototype**. It does not include
network delays, distributed validator communication, WAN-simulated latency, or
hardware security module (HSM) integration. Reported figures are therefore an upper
bound on isolated cryptographic performance.

## Software

| Component | Version |
|---|---|
| Python | 3.11.6 |
| liboqs-python | 0.14.1 |
| liboqs (C library) | 0.11.0 |
| Signature scheme | CRYSTALS-Dilithium2 (NIST FIPS 204; ML-DSA-44) |

## Cryptographic parameters (Dilithium2 / ML-DSA-44)

| Artifact | Size (bytes) |
|---|---|
| Public key | 1,312 |
| Secret key | 2,528 |
| Signature  | 2,420 |
| Claimed NIST security level | 2 |

## Experimental configuration

| Parameter | Value |
|---|---|
| Serial benchmark sample size | n = 500 |
| Concurrent scale-test sample size | n = 1,000 |
| Concurrency model | ThreadPoolExecutor, 4 worker threads |
| Block batch size | 50 votes/block |
| Number of blocks (scale test) | 20 |
| Validator stakes (Q-PnV) | 0.50 / 0.30 / 0.20 |
| Finalisation threshold | 0.67 (weighted approval) |
| Random seed (all randomised steps) | 42 |
| Adversarial suite total inputs | 550 (5 replay, 500 flood, 15 stripping, 25 bit-corruption, 5 signature-swap) |
| Legitimate votes (separate set) | 1,000 |

## Notes on units

Storage figures use **binary units** (1 GiB = 2^30 bytes). The national-scale JSON
projection is 327 GiB (equivalently 351 GB in decimal units); the CBOR projection is
167 GiB.
