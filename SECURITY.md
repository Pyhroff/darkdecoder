# Security Policy

## Reporting a Vulnerability

If you discover a security issue in this project, please report it responsibly:

- **Do not** open a public issue for security vulnerabilities.
- Use GitHub's private reporting: **Security** tab -> **Report a vulnerability**.

I will acknowledge within a few days and coordinate a fix and disclosure timeline.

## Analysis trust boundaries

DarkDecoder sends submitted analysis content to the configured Groq API for model-assisted analysis. Treat submitted source, prompts, and uploaded files as untrusted input and do not include secrets, credentials, private source code, or regulated data.

The local static-analysis layer does not execute submitted code. However, LLM-generated classifications and mappings can be influenced by adversarial input (prompt injection), so results require analyst validation.

Framework identifiers are drawn from the embedded reference corpus in the repository and may lag the live MITRE ATT&CK and ATLAS catalogs.

## Supported Versions

The latest release on the default branch receives security updates.

## Scope & Responsible Use

This project is for **authorized security testing and educational use only**.
Use it only against systems you own or have explicit written permission to test.
