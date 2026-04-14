# Security Policy

## Supported Versions

This is a portfolio project — the `main` branch is the only supported version. Older tags exist for historical reference only.

## Reporting a Vulnerability

If you think you've found a vulnerability in SentinelOps, please **do not open a public GitHub issue**. Instead:

1. Email the maintainer at m11k.08k3@gmail.com with the subject line `SECURITY: <short summary>`.
2. Include:
   - The affected module (siem / recon / ids / vault / core)
   - A minimal reproduction (PoC) if possible
   - Your assessment of impact
   - Whether you want credit in the eventual fix note

You should get an acknowledgement within 72 hours. I try to have a patch or mitigation within two weeks depending on severity.

## Scope

In scope:
- Auth bypasses (JWT, WebAuthn)
- Vault crypto weaknesses (key derivation, AES-GCM usage, audit log tampering)
- SSRF / RCE / path traversal in any API endpoint
- Injection into the SIEM log parsers
- Supply-chain issues (dependency, container base image)

Out of scope:
- Denial-of-service against the development stack
- Findings against third-party dependencies without a demonstrated path to exploit in SentinelOps
- Social-engineering the maintainer

## Responsible Use Reminder

The `recon` module intentionally ships active scanning capabilities. Running them against systems you do not own or have written authorisation to test is illegal in most jurisdictions. You accept all responsibility for how you use this tool.
