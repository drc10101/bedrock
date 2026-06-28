# Security Policy

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, email **security@infill.systems** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You should receive a response within 48 hours. If you do not, please follow up to ensure we received your message.

## Disclosure Policy

- We acknowledge all vulnerability reports within 48 hours
- We provide a timeline for fix within 5 business days
- We credit researchers in our changelog (unless anonymity is requested)
- We ask for 90 days before public disclosure to allow users to patch

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Active development |
| < 0.3   | Not supported |

## Security Architecture

Bedrock is designed with defense in depth:

- **Encryption at rest**: All data encrypted with AES-256-GCM, keys derived via HKDF
- **Identity-first**: Every node has a cryptographic identity, verified at every interaction
- **Consent-gated access**: Cross-silo data access requires cryptographic proof of consent
- **Audit chain**: SHA-256 hash chain provides tamper-evident audit trail
- **TLS enforcement**: All transport encrypted, downgrade detection active
- **Key isolation**: Silo-scoped keys, master key never stored in cleartext