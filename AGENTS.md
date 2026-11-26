# Workspace Engineering & Documentation Standards

All code, documentation, comments, identifiers, tests, and user-facing CLI/UI text in this repository must adhere strictly to formal, production-grade security and distributed-systems engineering standards.

## 1. Professional Terminology & Naming Rules

Do not use informal, hackathon-oriented, or placeholder terminology anywhere in documentation, source code, comments, test names, configuration files, or terminal output.

| Prohibited / Informal Term | Required Professional Replacement |
| :--- | :--- |
| `Mock Nodes`, `Mock Service(s)`, `mock` (outside unit-test stubs/fixtures) | **Service Nodes**, **Protected Services**, **Target Services**, or **Service Endpoints** |
| `Chaos Testing`, `chaos` | **Resilience Testing**, **Fault-Injection Testing**, or **Fault-Tolerance Verification** |
| `Sandbox`, `sandbox-ready` | **Isolated Test Environment**, **Verification Environment**, or **Modular / Self-Contained** |
| `Clean-Machine Setup` | **Environment Setup & Deployment** or **System Installation & Execution** |
| `Security Ground Rules` | **Engineering & Security Constraints** |
| `Hackathon`, `Track 4`, `Judges`, `5-minute demo`, `Demo Video`, `Submitter Notes` | Omit entirely, or reframe as **Security Compliance Matrix**, **Operational Walkthrough**, and **Verification Suite** |
| `Kill switch`, `catch attackers`, `superpower`, `bulletproof` | **Emergency Key Revocation**, **Threat Detection & Automated Containment**, and exact technical specifications |

## 2. Writing Style & Tone

- **Formal Engineering Prose:** Write clear, concise, objective technical sentences in third-person or imperative documentation style. Avoid hype, conversational phrasing, or promotional language.
- **Precision:** State exact algorithms, standards (e.g., NIST FIPS 203, FIPS 204, NIST IR 8547), protocols, and failure modes accurately.
- **Code & Documentation Alignment:** Every file path, module name, CLI command, configuration option, and domain-separation context string documented in Markdown must match the actual repository implementation.

## 3. Code Commenting Policy

- **No Unnecessary Comments:** Do not add comments to source or configuration files unless strictly required.
- **Self-Documenting Code:** Rely on clear identifiers, type annotations, and concise docstrings on modules, classes, and public functions rather than inline commentary.
- **Prohibited Comments:** Never add line-by-line narrations explaining what code does, decorative section dividers (`# ----`), step banners (`# --- Step 1 ---`), or trailing comments that restate variable/field names.
- **When Comments Are Permitted:** Add a concise comment *only* to document non-obvious **why** rationale—such as cryptographic ordering invariants (e.g., verify-before-decrypt), concurrency/locking hazards, platform-specific I/O semantics, or required linter directives (`# type: ignore`, `# noqa`).

## 4. Documentation Organization

- **`README.md`:** High-level project overview, problem statement, strategic standards context, solution summary, NIST FIPS 204 cryptographic foundation, enterprise use cases, and standards references. Cross-reference `docs/` for architecture, SDK, operational, testing, and threat-model documentation.
- **`docs/`:** Modular technical documentation organized by domain: `docs/architecture.md` (system architecture diagram, operational flows, verification matrix, folder-level repository layout, constraints), `docs/sdk/` (SDK reference), `docs/operations.md` (setup, CLI, web console), `docs/testing.md` (verification suite and observed benchmarks), and `docs/threat-model.md` (assumptions and stated limitations).
- **Folder-Level Documentation:** Architecture diagrams, control matrices, and repository structure trees in documentation must reference component directories (`src/sdk/`, `src/app/`, `tests/`, `config/`, `docs/`) rather than listing or tagging individual source files.
