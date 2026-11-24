# P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T.

### AI-Assisted Password Management & Cybersecurity Platform

**An experimental project exploring how far AI can go in developing, engineering, testing and improving security-critical software.**

---

## 1. Project Overview

P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T. is a locally operated desktop password manager and personal cybersecurity platform developed through AI-assisted software engineering.

The project explores the capabilities and limitations of AI throughout the software development lifecycle, using a real password management application as its testing ground.

Rather than limiting AI to generating isolated pieces of code, the experiment involves using AI to contribute to:

- Software architecture and system design.
- Cryptographic implementation.
- Feature development.
- Security engineering.
- Vulnerability analysis.
- Automated testing.
- Debugging and optimisation.
- Governance and risk management.
- Disaster recovery planning.
- Documentation and continuous improvement.

The objective is to investigate whether AI can contribute to the development of a complex, interconnected and security-sensitive software application while maintaining architectural consistency, functional reliability and defensible security practices.

**The password manager is the product. The AI-assisted development process is the experiment.**

## 2. Project Philosophy

The project follows several core principles:

| Principle | Description |
|---|---|
| Security first | Protecting credentials takes priority over convenience. |
| Local-first | Core functionality operates locally without mandatory cloud services. |
| Zero-trust | Access is verified and sensitive operations require appropriate authorisation. |
| Privacy | Credentials and sensitive information are protected from unnecessary exposure. |
| Modularity | Components have distinct responsibilities and interfaces. |
| Verification | AI-generated implementations must be tested. |
| Transparency | Development decisions, limitations and failures are documented. |
| Continuous improvement | Security and functionality are evaluated throughout development. |

## 3. Core Architecture

The application is organised into specialised components within `shield_core`.

| Component | Responsibility |
|---|---|
| `vault_engine.py` | Encrypted credential storage and database operations. |
| `key_management.py` | Key derivation, encryption key management and vault key handling. |
| `password_gen.py` | Cryptographically secure password and passphrase generation. |
| `mfa.py` | Vault authentication and multi-factor authentication. |
| `identity_access.py` | Authentication controls, rate limiting and trusted devices. |
| `adaptive_security.py` | Risk-based security requirements and re-authentication. |
| `security_audit.py` | Credential analysis, vulnerability detection and security scoring. |
| `e2ee.py` | Encrypted synchronisation and secure entry sharing. |
| `google_sync.py` | Google Password Manager integration and Google Drive support. |
| `recovery_backup.py` | Emergency recovery, backups, snapshots and restoration. |
| `audit_log.py` | Cryptographically verifiable security event history. |
| `governance_ops.py` | Security policies, risk management, incident response and disaster recovery. |

The desktop interface is implemented through `app.py` and `dialogs.py`.

## 4. Features and Capabilities

### 4.1 Encryption and Storage

The vault uses a layered cryptographic architecture.

- Argon2id master-password key derivation.
- Argon2id configuration: 64 MiB memory, 3 iterations and 4 lanes.
- KDF parameter upper bounds to reduce denial-of-service risks.
- AES-256-GCM authenticated encryption.
- RAM-only Vault Master Key (VMK).
- Independent random 256-bit Data Encryption Key (DEK) per record.
- Authenticated Additional Data (AAD) binding.
- SQLite database with Write-Ahead Logging.
- WAL checkpoint truncation during shutdown.
- Encrypted record manifest.
- SHA-256 record digests.
- Detection of unauthorised record modification, injection, deletion and ciphertext rollback.

The master password is never stored.

Credential records are encrypted individually, allowing the application to maintain separation between stored records.

### 4.2 Credential Management

The application supports eight credential types:

1. Website.
2. Application.
3. Email.
4. Secure Note.
5. Recovery Codes.
6. API Key / Token.
7. Wi-Fi.
8. Software Licence.

Additional organisation and management capabilities include:

- Categories.
- Custom tags.
- Favourite credentials.
- Custom key-value fields.
- Live search.
- Multi-filter credential library.
- Passwords hidden by default.
- Temporary password reveal.
- Automatic clipboard clearing.
- Configurable inactivity locking.

### 4.3 Advanced Password and Passphrase Generation

The password generator uses Python's cryptographically secure `secrets` module.

**Random password generation**

- Uppercase and lowercase characters.
- Numbers and special characters.
- Extended symbols.
- Custom additional characters.
- Ambiguous-character exclusion.
- Minimum digit requirements.
- Minimum symbol requirements.
- Configurable password length.
- Site-specific policy presets.

Available presets:

- Standard.
- Maximum.
- Banking.
- Legacy Alphanumeric.
- Wi-Fi WPA2/WPA3.
- API Token.

**Memorable passphrase generation**

- Diceware-style wordlists.
- Configurable word count.
- Custom separators.
- Capitalisation options.
- Optional numbers.
- Optional symbols.

**Live password analysis**

- Entropy estimation.
- Offline crack-time estimation.
- Live strength assessment.

### 4.4 Identity and Multi-Factor Authentication

**Vault authentication**

- Two-stage vault unlocking.
- RFC 6238 TOTP support.
- Compatibility with Google Authenticator, Microsoft Authenticator, Aegis and 2FAS.
- In-application QR code generation.
- Anti-replay time-step protection.
- Eight hashed one-time recovery codes.
- Persistent progressive authentication lockouts.

**Credential authentication**

- Built-in TOTP authenticator.
- Live rotating six-digit authentication codes.
- Countdown display.
- One-click code copying.
- Passkey status tracking.

**Device management**

- Trusted device registry.
- Device revocation.
- Authentication monitoring.
- Additional authentication for sensitive operations.

### 4.5 Adaptive Security Engine

The adaptive security engine applies deterministic, AI-independent access controls.

Security requirements depend on the sensitivity of an operation.

Examples:

| Operation | Security requirement |
|---|---|
| Username lookup | Normal access |
| Sensitive credential reveal | Optional re-authentication |
| Finance, email and work credential access | Additional security where configured |
| Vault export | Master password and MFA |
| Device changes | Master password and MFA |
| Security policy modifications | Master password and MFA |

The purpose is to apply additional security where it matters without unnecessarily obstructing ordinary operations.

### 4.6 Password Intelligence and Vulnerability Auditing

**Credential analysis**

- Weak password detection.
- Common password detection.
- Stale password identification.
- Missing MFA detection.
- Duplicate password detection.
- Real-time password reuse warnings.
- Configurable save-time warnings or hard blocks.

**Vault security assessment**

- Security health score from 0–100.
- Risk score from 0–100.
- Priority-ranked vulnerable accounts.
- Risk explanations.
- Recommended remediation actions.

**Website security checks**

- HTTP connection detection.
- Punycode lookalike detection.
- Built-in database of major breached websites.
- Website TLS certificate inspection.
- Security header inspection.

Supported security headers include:

- HSTS.
- CSP.
- X-Frame-Options.
- X-Content-Type-Options.

The live scanner includes redirect-aware SSRF protections.

**Have I Been Pwned integration**

Opt-in breach checking uses the k-anonymity model. Only the first five characters of a password's SHA-1 hash are transmitted for the lookup.

**Reporting**

- Redacted Markdown security audit reports.

### 4.7 End-to-End Encryption and Synchronisation

The application supports encrypted multi-device synchronisation.

- Zero-knowledge encrypted synchronisation.
- Encrypted `.shield.enc` files.
- Conflict-safe merging.
- Google Drive support.
- OneDrive support.
- Dropbox support.
- USB-based transfer.

Cloud storage providers receive encrypted synchronisation files rather than the plaintext vault contents.

**Encrypted credential sharing**

- Ed25519 sender signatures.
- X25519 recipient public-key encryption.
- HKDF-SHA256 key derivation.
- AES-256-GCM encryption.
- Alternative one-time Argon2id passphrase-based sharing.

The recipient can verify the sender's signature and decrypt the shared entry using the appropriate credentials.

### 4.8 Google Password Manager Integration

Consent-gated integration with Google Password Manager.

- Direct access to Google Password Manager.
- Google Password Checkup access.
- Official CSV import.
- Official CSV export.
- Optional secure file shredding.
- Google Drive encrypted synchronisation folder detection.

Google Password Manager remains a separate service. This application provides integration and portability rather than claiming to replace Google's internal security infrastructure.

### 4.9 Emergency Recovery and Backup Management

The application uses a zero-reset recovery model.

**Emergency recovery**

- 200-bit offline Recovery Key.
- Recovery Key wrapping of the VMK.
- Recovery without a conventional master-password reset.
- No hidden master-password reset backdoor.

**Encrypted backups**

- Argon2id-protected backups.
- AES-256-GCM encryption.
- SHA-256 checksums.
- Ed25519 signatures.
- Versioned `.shield.enc` files.
- Automatic rolling SQLite snapshots.
- Maximum of five rolling snapshots.
- JSON portability.
- Non-destructive restoration integrity testing.

### 4.10 Cryptographic Audit Logging

The application includes a tamper-evident security event log.

- SHA-256 hash-chained events.
- Ed25519 digital signatures.
- Individual event verification.
- Chain integrity verification.
- Strict credential and secret redaction.
- Exportable JSON proof bundles.

This allows the integrity of recorded events to be independently checked against the corresponding verification material.

### 4.11 Governance and Security Operations

The governance engine introduces operational security management into the password manager.

**Enforceable security policies**

Eight policy controls:

- Minimum password length.
- Password reuse warnings or blocking.
- Maximum password age.
- HTTPS requirements.
- MFA requirements for high-value accounts.
- Vault MFA requirements.
- Recovery Kit requirements.
- Backup cadence.

A live compliance percentage reflects policy adherence.

**Risk register**

- Likelihood × Impact scoring.
- Risk scores from 1–25.
- Automatically synthesised risks.
- Custom operational risks.
- Open.
- Mitigating.
- Accepted.
- Closed.

**Incident response**

Five NIST-aligned incident response playbooks.

- Encrypted interactive incident checklists.
- Incident tracking.
- One-click emergency containment.
- Forensic snapshot creation.
- Revocation of other trusted devices.
- Critical signed security event.
- Vault lockdown.

**Patching posture**

A local, zero-telemetry environment scanner checks:

- Python.
- OpenSSL.
- SQLite3.
- `cryptography`.
- `qrcode`.
- Argon2id KDF configuration.
- Operating system security baselines.

The scanner provides copyable update commands.

**Disaster recovery**

- Three guided recovery runbooks.
- Live disaster recovery readiness drill.
- SQLite B-tree integrity testing.
- Record manifest verification.
- Ed25519 audit chain verification.
- Recovery Kit verification.
- Rolling snapshot verification.

## 5. Desktop Interface

The desktop application contains seven primary navigation views.

| View | Function |
|---|---|
| Security Dashboard | Security overview and cybersecurity scorecard. |
| Credential Library | Manage stored credentials. |
| Health & Risk Audit | Analyse password and account security. |
| Identity & Devices | Authentication, MFA and trusted devices. |
| Governance & IR | Policies, risk register and incident response. |
| Backup & Recovery | Backups, recovery and disaster recovery. |
| Security Audit Log | Inspect and verify recorded events. |

Additional interface features:

- Dark theme.
- Light theme.
- Live theme switching.
- Seven primary views.
- Eight dialogs.

## 6. AI-Assisted Development Experiment

A major purpose of this project is to investigate how far AI can contribute to developing a complete software application.

The experiment uses a real cybersecurity application to evaluate AI's ability to work across interconnected engineering disciplines.

### Areas of investigation

**Software engineering**
- Architecture design.
- Modular development.
- Code generation.
- Refactoring.
- Debugging.

**Cybersecurity**
- Cryptographic implementation.
- Authentication systems.
- Access control.
- Vulnerability identification.
- Defensive engineering.

**Testing and verification**
- Automated testing.
- Static analysis.
- Security testing.
- GUI verification.
- Regression testing.
- Failure analysis.

**Systems engineering**
- Component integration.
- Data flow.
- Error handling.
- Recovery design.
- Operational reliability.

### Evaluation principles

AI-generated work is evaluated through:

1. Functional correctness.
2. Security properties.
3. Maintainability.
4. Architectural consistency.
5. Test results.
6. Performance.
7. Ability to identify and correct implementation errors.

The experiment does not assume that AI-generated code is correct simply because it compiles or passes a limited test suite.

Development failures, corrections and limitations are part of the research.

## 7. Verification and Current Status

The current development summary reports:

| Verification area | Reported result |
|---|---:|
| Python files passing static and zero-PII checks | 17/17 |
| Automated security tests passing | 12/12 |
| Primary UI views verified | 7/7 |
| Dialogs verified | 8/8 |

These results represent the current reported verification state.

They do not establish that every possible attack has been tested or that the application has passed an independent penetration test, cryptographic audit or formal verification process.

## 8. Running the Application

**Windows**

The application can be launched using:

```bat
run.bat
```

Main application entry point:

```text
app.py
```

Core functionality:

```text
shield_core/
```

Automated security tests:

```text
test_shield_vault.py
```

## 9. Security Disclaimer

This is an experimental software project.

Although the application incorporates modern cryptographic primitives and security engineering practices, implementation correctness and security require continued independent verification.

In particular:

- Passing automated tests does not prove the absence of vulnerabilities.
- Cryptographic algorithms can be implemented incorrectly.
- Local malware or a compromised operating system may access unlocked data.
- Cloud synchronisation providers may observe file metadata even when file contents are encrypted.
- Secure deletion cannot be guaranteed on all storage devices.
- Network-based security checks introduce additional risks.
- Backup and recovery mechanisms must be independently tested.

Do not rely on the application for critical production credentials until it has undergone appropriate independent security review.

## 10. Long-Term Direction

The long-term objective is to continue expanding the application while evaluating AI's ability to participate in increasingly complex software engineering tasks.

Future development should prioritise:

- Independent security assessment.
- Expanded automated test coverage.
- Adversarial testing.
- Cryptographic implementation review.
- Performance optimisation.
- Accessibility and usability.
- Improved threat modelling.
- More comprehensive recovery testing.
- Continued architectural refinement.

The project is intended to demonstrate both the capabilities and limitations of AI-assisted software development through a real, functioning application.

---

**P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T.**

*A password manager built through an experiment in AI-assisted engineering.*
