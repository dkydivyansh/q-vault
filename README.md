# Q-Vault Sentinel

**Post-Quantum Zero-Trust Messaging Gateway, Crash-Safe Key Control Plane, and Deterministic Lateral-Movement Watchdog**

> **NIST FIPS 203 & FIPS 204 Aligned**

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Why Now? The Post-Quantum & Zero-Trust Inflection Point](#3-why-now-the-post-quantum--zero-trust-inflection-point)
4. [Proposed Solution & Capabilities](#4-proposed-solution--capabilities)
5. [Cryptographic Foundation: Grounding in NIST FIPS 204](#5-cryptographic-foundation-grounding-in-nist-fips-204)
6. [Architecture Overview](#6-architecture-overview)
7. [Enterprise Use Cases](#7-enterprise-use-cases)
8. [References & Standards](#8-references--standards)

---

## 1. Executive Summary

Dropping a post-quantum encryption algorithm into an application does not make a system secure. As **NIST FIPS 204 (Clause 14)** explicitly warns, mathematical conformance to a cryptographic standard does not guarantee overall system security if private keys cannot rotate cleanly, revoked devices remain accepted, crashed nodes corrupt key state, or attackers holding stolen valid credentials move silently across internal services.

**Q-Vault Sentinel** bridges the gap between standardized post-quantum cryptography and resilient zero-trust operations. It unites four tightly coupled subsystems into a single closed-loop security architecture:

1. **Quantum-Safe Data Protection:** Hybrid forward-secret sessions (`X25519 + ML-KEM-768`), authenticated encryption (`AES-256-GCM` with strict recipient binding), and post-quantum identity signatures (`ML-DSA-65`).
2. **Crash-Safe Key Lifecycle Control:** Zero-downtime key rotation with documented grace cutoffs, sub-second cross-node revocation with latency telemetry, atomic Write-Ahead Log (WAL) crash recovery, and authenticated key backups.
3. **Tamper-Evident, Injection-Proof Audit Telemetry:** Canonicalized single-line JSON logging chained via `SHA-256` and signed at checkpoints using `ML-DSA` for non-repudiation.
4. **Deterministic, Zero-AI Anomaly Detection & Active Response:** A clock-skew-resilient rule and directed service-graph engine that distinguishes routine administration from privilege escalation and lateral movement automatically revoking compromised keys in real time.

---

## 2. Problem Statement

Modern distributed applications consist of interconnected internal services (Authentication, Billing, Vaults, Databases, Admin Consoles) exchanging sensitive messages and files continuously. Conventional security stacks leave three systemic vulnerabilities exposed:

### 2.1 "Harvest Now, Decrypt Later" (Quantum Exposure)
Classical public-key cryptosystems relying on integer factorization (RSA) and discrete logarithms (ECDH, ECDSA, Ed25519) are vulnerable to large-scale, fault-tolerant quantum computers. Adversaries already capture encrypted enterprise traffic and long-lived archives today with the intent to decrypt them once quantum hardware matures.

### 2.2 Operational Fragility Under Key Churn & Failures
Encryption breaks down in production during operational edge cases:
* **Abrupt key rotations** drop active in-flight file transfers, while permissive rotations leave expired keys accepted indefinitely.
* **Delayed revocations** allow a stolen device or compromised service key to keep exfiltrating data across nodes that have not refreshed their blocklists.
* **Unclean crashes and damaged backups** mid-rotation can leave a service in an inconsistent state, resurrect previously revoked keys, or silently load corrupted key material.

### 2.3 The Valid-Credential Blind Spot & Log Forgery
Cryptographic handshakes only prove that a caller holds a valid key they cannot detect when an attacker steals an active credential, abuses legitimate access to pivot laterally into restricted services, or injects forged newline payloads into plaintext logs to obscure activity or frame another identity.

---

## 3. Why Now? The Post-Quantum & Zero-Trust Inflection Point

Deploying crypto-agile, zero-trust infrastructure is no longer a speculative research exercise  mandatory transition timelines are actively taking effect:

* **Finalized NIST PQC Standards (August 2024):** NIST formally standardized **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)** after an eight-year public evaluation of 82 candidate submissions, giving engineers vetted, drop-in primitives.
* **NIST IR 8547 Transition Deadlines (Finalized October 2026):** NIST's post-quantum transition roadmap schedules formal deprecation of quantum-vulnerable public-key algorithms (RSA, ECDSA, EdDSA, ECDH) after **2030** and complete disallowance after **2035**, while affirming hybrid key establishment (`X25519 + ML-KEM`) as a durable migration path.
* **NSA CNSA 2.0 Mandates (Effective January 2027):** Acquisition requirements for CNSA 2.0 quantum-resistant algorithms begin taking force immediately, driving commercial and regulated infrastructure toward PQC-ready identity planes.
* **Demand for Explainable, Deterministic Detection:** Security operations teams increasingly reject opaque AI/ML anomaly detectors that generate unexplainable false positives or cannot satisfy audit inquiries. Deterministic graph and rule engines provide transparent, mathematically verifiable attribution for every alert.

---

## 4. Proposed Solution & Capabilities

Q-Vault Sentinel is a self-contained, modular security platform written in Python using the vetted `pyca/cryptography` library, SQLite in Write-Ahead Log (WAL) mode, and a deterministic directed service-graph engine built on Python's standard library.

| Problem Domain | Q-Vault Sentinel Solution |
| :--- | :--- |
| **Quantum-Vulnerable Key Exchange & Signatures** | Hybrid ephemeral `X25519 + ML-KEM-768` key establishment combined via `HKDF-SHA256`, paired with `ML-DSA-65` (FIPS 204) identity signatures. |
| **Past Traffic Compromise** | Strict **Perfect Forward Secrecy (PFS)**: ephemeral keypairs are generated per session and immediately wiped after key derivation. |
| **Replay, Tampering, Packet Loss & Session Hijacking** | `AES-256-GCM` with `sender_id`, `recipient_id`, `key_epoch`, and `seq_num` bound into AAD; sliding bitmask anti-replay window; chunked reassembly with strict invalid-discard; peer-ID-bound session resumption tickets. |
| **Rotation Downtime & Revocation Lag** | Versioned keys with a configurable **30-second grace window** followed by a hard cutoff; signed `ML-DSA` revocation broadcasts with monotonic epoch counters and measured last-node propagation telemetry. |
| **Crash Corruption & Bad Backups** | Atomic SQLite WAL transactions (`BEGIN IMMEDIATE ... COMMIT`) guaranteeing consistent key recovery and persistent revocations; `AES-256-GCM`-encrypted, `ML-DSA`-signed backups that reject single-bit tampering. |
| **Log Injection & Audit Tampering** | Strict canonical single-line JSON serialization escaping all control characters (`\n`, `\r`), linked in a `SHA-256` hash chain with signed `ML-DSA` checkpoints. |
| **Lateral Movement, Privilege Escalation & Clock Skew** | A **Zero-AI** detector featuring a configurable clock-skew reorder buffer ($\pm 5\text{ s}$ tolerance with explicit `ordering_uncertain` flags), context-aware admin rules, and a directed service-access graph that triggers automatic key revocation. |

---

## 5. Cryptographic Foundation: Grounding in NIST FIPS 204

Q-Vault Sentinel directly operationalizes the security assurances and implementation requirements specified in **NIST FIPS 204 (*Module-Lattice-Based Digital Signature Standard*, August 2024)**, which standardizes **ML-DSA** (derived from CRYSTALS-Dilithium) based on the hardness of the **Module Learning With Errors (MLWE)** and **SelfTargetMSIS** lattice problems.

### 5.1 Parameter Set Selection (FIPS 204, Section 4, Tables 1 & 2)

| Parameter Set | NIST Security Category | Public Key Size | Private Key Size | Signature Size | Role in Q-Vault Sentinel |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `ML-DSA-44` | Category 2 | 1,312 bytes | 2,560 bytes | 2,420 bytes | Optional low-overhead profile |
| **`ML-DSA-65`** *(Default)* | **Category 3** | **1,952 bytes** | **4,032 bytes** | **3,309 bytes** | **Default node identity, handshakes, revocations & audit checkpoints** |
| `ML-DSA-87` | Category 5 | 2,592 bytes | 4,896 bytes | 4,627 bytes | High-assurance Root Authority / CNSA 2.0 profile |

### 5.2 Direct Mapping of FIPS 204 Mandates into Engineering Controls

1. **Strong Existential Unforgeability (SUF-CMA) & Non-Repudiation *(Abstract, Sec. 1.1, Sec. 3.1)*:** Every key rotation directive, revocation broadcast, handshake transcript, and audit checkpoint is signed with `ML-DSA-65` so neither compromised nodes nor malicious insiders can forge or repudiate historical actions.
2. **Strict Key-Usage Separation *(Announcement Clause 8)*:** FIPS 204 mandates that digital signature keypairs shall not be used for other purposes. Q-Vault Sentinel maintains strictly segregated `ML-DSA` signing identities and `X25519 + ML-KEM` key-establishment identities.
3. **Default "Hedged" Signing *(Sec. 3.4, Sec. 3.6.1, Alg. 2)*:** Signing operations rely on FIPS 204's hedged mode, combining fresh OS CSPRNG entropy (`rnd`) with the private signing seed `K` and message representative $\mu$ to mitigate differential fault and timing side-channel attacks.
4. **Protocol Domain Separation via Context Strings `ctx` *(Sec. 5.2, Sec. 5.3, Alg. 2 & 3)*:** FIPS 204 supports a domain-separation context string (`|ctx|` $\le 255$ bytes). Q-Vault Sentinel enforces distinct context tags—`qvault-handshake-v1`, `qvault-epoch-v1`, `qvault-revoke-v1`, `qvault-backup-v1`, `qvault-log-v1`, and `qvault-resumption-v1`—preventing cross-protocol signature replay.
5. **Strict Input Length Validation & BUFF Binding *(Sec. 3.3, Sec. 3.6.2, Alg. 3)*:** Verification explicitly validates public-key and signature byte lengths before processing and relies on ML-DSA's built-in Beyond UnForgeability Feature (BUFF), which hashes the public key (`tr = H(pk, 64)`) directly into the message representative $\mu$.
6. **Pure ML-DSA vs. Pre-Hash `HashML-DSA` *(Sec. 5.4)*:** Following NIST's guidance that pure ML-DSA is preferred for standard protocols, Q-Vault Sentinel uses pure `ML-DSA` for all control messages and hash-chain checkpoints, while bulk files are chunked and authenticated via `AES-256-GCM`.
7. **Destruction of Sensitive Intermediates & Seed Protection *(Sec. 3.6.3)*:** Ephemeral private keys and intermediate signing material are cleared immediately after derivation. Backups and persistent signing keys are protected at rest under AES-GCM Key Encryption Key (KEK) controls.

---

## 6. Architecture Overview

Q-Vault Sentinel separates responsibilities across a composable security SDK (`src/sdk/`), a runnable control-plane and service application layer (`src/app/`), and an automated verification suite (`tests/`), uniting **Control Plane**, **Data Plane**, **Telemetry Plane**, and **Detection & Response** in a single closed-loop platform.

For detailed system documentation, see:

* **[System Architecture & Flows](docs/architecture.md)** — Architecture diagram, end-to-end flows, security verification matrix, folder structure, and engineering constraints
* **[SDK Reference](docs/sdk/overview.md)** — Core post-quantum cryptography, authority, gateway, ledger, and watchdog interfaces (`src/sdk/`)
* **[Operations & Deployment Guide](docs/operations.md)** — Environment setup, configuration, operator CLI, and Web Console usage (`src/app/`)
* **[Verification & Benchmarks](docs/testing.md)** — Automated `tests/` coverage, benchmark methodology, and observed metrics
* **[Threat Model & Limitations](docs/threat-model.md)** — Adversary capabilities, trust assumptions, and explicit design limits

---

## 7. Enterprise Use Cases

* **Inter-Bank Settlement & Financial Messaging:** Protects high-value payment instructions against "Harvest Now, Decrypt Later" interception while delivering mathematically non-repudiable `ML-DSA` audit logs for regulatory compliance.
* **Multi-Hospital Electronic Health Record (EHR) Exchanges:** Secures patient histories that require multi-decade confidentiality (well beyond the 2035 quantum transition horizon) while detecting compromised clinical credentials accessing unauthorized services.
* **Defense, Autonomous Fleet & Industrial OT Control Links:** Enforces CNSA 2.0-aligned signed command streams and rapid lost-device revocation across distributed edge nodes operating under intermittent connectivity and clock drift.
* **Enterprise Microservice & Secret-Vault Control Planes:** Replaces static API keys and legacy RSA/ECDSA internal PKIs with short-lived, forward-secret hybrid PQC sessions and deterministic service-graph containment.

---

## 8. References & Standards

1. **National Institute of Standards and Technology (2024).** *Module-Lattice-Based Digital Signature Standard (ML-DSA).* Federal Information Processing Standards Publication **NIST FIPS 204**. `https://doi.org/10.6028/NIST.FIPS.204`
2. **National Institute of Standards and Technology (2024).** *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).* Federal Information Processing Standards Publication **NIST FIPS 203**. `https://doi.org/10.6028/NIST.FIPS.203`
3. **National Institute of Standards and Technology (2024).** *Stateless Hash-Based Digital Signature Standard (SLH-DSA).* Federal Information Processing Standards Publication **NIST FIPS 205**. `https://doi.org/10.6028/NIST.FIPS.205`
4. **National Institute of Standards and Technology (2026).** *Transition to Post-Quantum Cryptography Standards.* **NIST IR 8547**.
5. **Barker, E. (2020).** *Recommendation for Key Management: Part 1 — General.* **NIST SP 800-57 Part 1, Rev. 5**. `https://doi.org/10.6028/NIST.SP.800-57pt1r5`
6. **Cremers, C., Düzlü, S., Fiedler, R., Janson, C., & Fischlin, M. (2021).** *BUFFing Signature Schemes Beyond Unforgeability and the Case of Post-Quantum Signatures.* IEEE Symposium on Security and Privacy (SP). `https://doi.org/10.1109/SP40001.2021.00093`
7. **Lyubashevsky, V. (2009).** *Fiat-Shamir with Aborts: Applications to Lattice and Factoring-Based Signatures.* ASIACRYPT 2009. `https://doi.org/10.1007/978-3-642-10366-7_35`
8. **Langlois, A., & Stehlé, D. (2015).** *Worst-Case to Average-Case Reductions for Module Lattices.* Designs, Codes and Cryptography, 75(3), 565–599.
9. **Vetted Cryptographic Libraries & Open-Source Architectural References:**
   * Python Cryptographic Authority (`pyca/cryptography`): `https://github.com/pyca/cryptography`
   * Open Quantum Safe (`open-quantum-safe/liboqs-python`): `https://github.com/open-quantum-safe/liboqs-python`
   * Hybrid PQC Envelope Reference Pattern (`scottdhughes/post-quantum-mcp`): `https://github.com/scottdhughes/post-quantum-mcp`
   * Hash-Chained Audit Log Reference Pattern (`sariyarizwan/tamperlog`): `https://github.com/sariyarizwan/tamperlog`
