# SecureChain

PKI-based digital forensic evidence integrity and chain-of-custody verification system.

SecureChain models how a forensics lab can prove that a piece of digital evidence has not been altered, and that every examiner who touched it can be cryptographically identified, in order, with no gaps. It combines a small X.509 certificate authority, SHA-256 evidence hashing, RSA-PSS digital signatures, and a hash-linked custody chain, then includes an attack simulation suite that tries to break it five different ways.

## Why

Traditional chain-of-custody logs are just paper trails or spreadsheet entries — easy to forge, easy to reorder, and impossible to verify after the fact. SecureChain replaces that with a structure where every custody entry is signed by an examiner's PKI-issued certificate and cryptographically linked to the entry before it, so tampering, reordering, deletion, or impersonation all become mathematically detectable rather than something a court has to take on trust.

## How it works

**Certificate Authority (`ca.py`)**
A self-contained Root CA generates a 3072-bit RSA key (encrypted at rest with AES via `BestAvailableEncryption`), then issues 2048-bit RSA certificates to individual examiners. Examiner certificates are constrained with strict `KeyUsage` extensions (signature-only, no `keyCertSign`), carry a 365-day validity window, and can be revoked through a signed X.509 CRL. `verify_certificate()` checks the CA signature, validity dates, CRL revocation status, and key usage on every certificate before it's trusted.

**Evidence packaging (`evidence.py`)**
Evidence files are hashed with SHA-256 using 8MB chunked reads, so large disk images don't need to be loaded into memory at once. Each evidence package is serialized to disk as strictly deterministic JSON (sorted keys, no whitespace) so hashing is byte-for-byte reproducible.

**Chain of custody (`examiner.py`)**
Each custody action is captured as a chain entry containing a sequence number, the examiner's identity (pulled from their certificate), a timestamp, a `previous_hash` linking back to the prior entry (or the original evidence hash for the first entry), and the examiner's PEM certificate. The entry is signed with RSA-PSS over a deterministic JSON payload. Critically, before an examiner is allowed to sign a new entry, the entire existing chain is re-verified from scratch — if it's already broken, the examiner cryptographically refuses to add to it.

**Independent verification (`verify.py`)**
`verify_chain()` walks the full custody chain from the original evidence hash forward, checking sequence numbers, hash linkage, certificate validity (including CRL status), and the RSA-PSS signature on every single entry. It stops at the first broken entry and reports exactly what failed.

**Attack simulations (`attack_sim.py`)**
Four adversarial scenarios are included to demonstrate what the verifier catches:
1. **Evidence tampering** — swapping the recorded evidence hash for a fake one
2. **Chain injection** — inserting a forged entry mid-chain and renumbering subsequent entries
3. **Certificate spoofing** — signing an entry with a self-signed "rogue CA" certificate instead of one issued by the real CA
4. **Entry deletion / replay** — removing an entry and re-indexing the remaining sequence numbers to hide the gap

**End-to-end demo (`demo.py`)**
Runs the full lifecycle: generates the Root CA, issues certificates to two examiners, creates an evidence package, has both examiners sign custody entries, verifies the clean chain, then runs all four attacks against copies of that chain (plus a bonus scenario revoking an examiner's certificate mid-chain) and prints a pass/fail report for each.

## Project structure

```
SecureChain/
├── ca.py            # Root CA, certificate issuance, CRL, certificate verification
├── evidence.py       # Evidence hashing and deterministic package serialization
├── examiner.py        # Chain entry creation, signing, pre-sign chain verification
├── verify.py          # Independent chain verification and reporting
├── attack_sim.py        # Adversarial test cases against the chain
├── demo.py            # End-to-end demo: setup -> sign -> verify -> attack
├── requirements.txt      # Python dependencies
└── certs/             # Generated CA key/cert, examiner credentials, CRL (gitignored output)
```

## Requirements

- Python 3.9+
- [`cryptography`](https://pypi.org/project/cryptography/) (the only third-party dependency)

```bash
pip install -r requirements.txt
```

This repo expects a `config.py` defining paths and key sizes (`CERTS_DIR`, `EXAMINERS_DIR`, `CRL_DIR`, `CA_KEY_PATH`, `CA_CERT_PATH`, `CRL_PATH`, `CA_KEY_SIZE`, `EXAMINER_KEY_SIZE`, `DEFAULT_CA_PASSWORD`, `DEFAULT_EXAMINER_PASSWORD`) — add one matching your local layout if it isn't already present.

## Usage

Run the full demo, which sets up the CA, issues examiner certs, builds an evidence package, signs a clean chain, verifies it, then runs all attack simulations:

```bash
python demo.py
```

Expected output includes a clean PASS report for the legitimate chain, followed by FAIL reports for each attack scenario, each naming the exact entry and reason the verifier rejected it (broken hash linkage, invalid signature, untrusted certificate, sequence mismatch, or revoked certificate).

## Cryptographic design notes

- **CA key**: RSA-3072, PKCS8, encrypted at rest
- **Examiner keys**: RSA-2048, PKCS8, encrypted at rest, signature-only key usage
- **Chain entry signatures**: RSA-PSS with SHA-256, MGF1, max salt length
- **Hashing**: SHA-256 throughout, both for evidence files (chunked) and for chain entries (deterministic JSON)
- **Revocation**: Standard X.509 CRL, signed by the CA, checked on every certificate verification

## Disclaimer

This is an educational/portfolio project demonstrating PKI and forensic chain-of-custody concepts. It is **not production-ready as-is**: the CA and examiner keys are encrypted with hardcoded default passwords (`DEFAULT_CA_PASSWORD`, `DEFAULT_EXAMINER_PASSWORD` in `config.py`), there's a single CA with no multi-party control, and there's no OCSP/CRL distribution infrastructure. A real deployment would need hardware-backed key storage (HSM or similar), per-deployment secrets management, and proper CRL/OCSP distribution.

## Author

Built by [Lokesh Acharya](https://github.com/LokeshAcharya).
