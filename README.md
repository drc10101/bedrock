# BEDROCK

Trade Secret — InFill Systems, LLC
All rights reserved. No public distribution.

## Structure

```
BEDROCK/
├── core/       Runtime: identity fabric, encrypted-at-rest networking, key management
├── sdk/        Developer toolkit: APIs, client libraries, primitives
├── docs/       Architecture specs, API design, internal documentation
└── tests/      Test suites for core and SDK
```

## Rules

- **No public repos.** This project never touches GitHub, GitLab, or any public host.
- **No cloud sync.** No OneDrive, no Dropbox, no iCloud for this directory.
- **No secrets in code.** Keys and credentials go in .env files (gitignored).
- **Every node is a user.** This is the core principle. Every compute endpoint has an identity, and everything between them is ciphertext.
- **Encrypted at rest, always.** Data exists in clear text only at the consuming endpoint, only for the minimum time required.
- **Self-hosted first.** The architecture must work without any Bedrock-operated infrastructure.

## Relationship to InFill

InFill is the first vertical application built on Bedrock. Healthcare proved the architecture. Bedrock extracts the reusable patterns and opens them to every vertical — banking, investment, insurance, defense, and beyond.