# Dilithium-Based Post-Quantum Blockchain Prototype

This repository contains the **original baseline implementation** of the post-quantum blockchain prototype evaluated and subsequently extended in the study:

**Implementation and Evaluation of a Dilithium-Based Post-Quantum Blockchain Prototype**

The repository represents the earlier single-machine prototype and the initial experimental codebase developed using the **pre-standardization CRYSTALS-Dilithium2 parameter set**.

It is retained as the original project repository for transparency and reproducibility of the baseline implementation.

---

## Repository Scope

The code in this repository corresponds to the **original baseline version of the prototype**.

It includes the core implementation used to investigate the integration of post-quantum digital signatures into a blockchain-style voting workload, including the principal components required for:

* key generation;
* post-quantum signing and verification;
* transaction and vote construction;
* block creation;
* validator-based approval;
* blockchain validation;
* baseline single-machine execution; and
* the original performance evaluation workflow.

This repository therefore documents the starting implementation from which the later experimental study was developed.

---

## Relationship to the Current Study

The current manuscript substantially extends the original prototype beyond the experiments represented by this repository.

The extended evaluation reported in the manuscript includes:

* comparison of the original CRYSTALS-Dilithium2 implementation with standardized **ML-DSA-44**;
* cryptographic primitive benchmarking;
* workload-scaling experiments;
* weighted-validator approval experiments;
* validation and security-control experiments;
* identity-binding analysis;
* serialization comparison between JSON and CBOR;
* concurrency experiments;
* single-host multi-process distributed emulation;
* deadline and coordination testing; and
* audited reproduction and validation of the reported results.

These additional experiments were performed as part of the extended study and are **not all represented by the historical source code contained in this repository**.

The repository should therefore be interpreted as the **original baseline codebase**, rather than as the complete execution package for every experiment in the current manuscript.

---

## Experimental Data for the Current Manuscript

The datasets generated and analyzed for the extended study are provided separately in the **reviewer-access archive accompanying the manuscript submission**.

That archive contains the original single-machine evaluation files and the (n = 1000) result files, together with the extended raw and audited-derived datasets supporting the:

* cryptographic comparison;
* workload-scaling analysis;
* weighted-approval experiments;
* security-control experiments;
* serialization experiments;
* concurrency analysis; and
* single-host distributed-emulation experiments.

The reviewer archive also contains the source data supporting the manuscript figures and the final **E1–E8** and **F0–F10** result tables.

A durable public repository DOI has not yet been assigned to these extended datasets.

---

## Baseline Cryptographic Configuration

The original implementation in this repository was developed using the **pre-standardization CRYSTALS-Dilithium2 parameter set**.

The current manuscript additionally evaluates migration to the standardized **ML-DSA-44** scheme defined under FIPS 204.

These configurations should not be interpreted as identical implementations. The distinction between the legacy Dilithium2 implementation and the standardized ML-DSA-44 implementation is explicitly preserved in the current study.

---

## Reproducibility Scope

This repository is intended to preserve the original implementation and baseline workflow.

Accordingly:

* baseline behavior can be inspected directly from the historical source code;
* the repository documents the architecture from which the extended study originated;
* some experiments in the current manuscript were performed using later experimental and auditing harnesses;
* the extended experimental datasets are supplied separately with the manuscript submission; and
* results in the current manuscript should be interpreted using the experimental protocol and evidence described in the manuscript and its accompanying reviewer-access archive.

The repository is intentionally retained as the original codebase rather than being retrospectively modified to make it appear identical to the later experimental environment.

---

## Important Legacy-Code Note

Some components in this repository represent **legacy prototype behavior** that was subsequently examined during the extended study.

In particular, the current manuscript reports security and coordination analyses that identified implementation-level behaviors requiring explicit validation or correction.

These findings are part of the research contribution of the extended study and should not be interpreted as undocumented modifications to the historical baseline.

Where corrective logic was evaluated, the distinction between:

1. the original behavior,
2. the identified issue, and
3. the separately evaluated correction

is maintained in the manuscript and accompanying experimental evidence.

---

## Research Context

The purpose of the project is not only to benchmark a post-quantum signature primitive.

The extended study examines how migration to post-quantum signatures interacts with the surrounding blockchain implementation, including:

* validation logic;
* validator approval;
* identity binding;
* data representation;
* concurrency; and
* coordination behavior.

The results therefore distinguish **cryptographic primitive performance** from **application-level correctness and system-level behavior**.

---

## Current Manuscript

**Title:**
*Implementation and Evaluation of a Dilithium-Based Post-Quantum Blockchain Prototype*

The manuscript evaluates the original prototype together with an extended experimental framework designed to characterize both cryptographic and application-level effects of post-quantum migration.

---

## Data Availability

The original project source code is publicly available in this repository.

The extended raw and audited-derived datasets supporting the current manuscript are provided in the reviewer-access archive accompanying the submission.

No durable public repository DOI has yet been assigned to the extended datasets.

---

## License and Use

This repository is provided for academic research, inspection, and reproducibility purposes.

Users of the code should take into account that it contains an **experimental research prototype** and historical baseline components. It is not intended to provide a production-ready blockchain, voting system, or security-critical deployment.

---

## Contact

For questions concerning the repository or the associated research:

**Ahmed Abdellatif**
Misr University for Science and Technology
6th of October City, Giza, Egypt
