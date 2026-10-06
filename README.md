# DarkDecoder

**Dual-framework threat intelligence for malware and AI/ML attacks.**

> Analyze suspicious code or AI-related inputs and turn them into structured **MITRE ATT&CK + MITRE ATLAS** intelligence, with risk scoring, technique mapping, IOCs, attack timelines, and exportable reports.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/) [![Streamlit](https://img.shields.io/badge/Streamlit-1.65-FF4B4B.svg)](https://streamlit.io/) [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) [![CI](https://github.com/Pyhroff/darkdecoder/actions/workflows/ci.yml/badge.svg)](https://github.com/Pyhroff/darkdecoder/actions/workflows/ci.yml)

## Why DarkDecoder?

Traditional threat-intelligence workflows often treat conventional malware and AI-specific attacks as separate problems. DarkDecoder puts both into one analyst-facing workflow:

**Input → analysis → framework mapping → risk → evidence → report**

It is designed as a **triage and intelligence aid**, not as a replacement for sandboxing, EDR, SIEM, or human analysis.

## Analysis modules

### 1. Malware Scanner — MITRE ATT&CK
- Decode common obfuscation such as Base64 and hex.
- Identify suspicious execution, persistence, networking, and payload behavior.
- Extract indicators such as IPs, domains, URLs, paths, and registry artifacts.
- Produce a 1–10 danger score with reasoning.
- Map observed behavior to ATT&CK techniques.
- Generate remediation guidance and analyst-friendly summaries.

### 2. AI Threat Analyzer — MITRE ATLAS
- Analyze AI/ML attack descriptions and suspicious AI-related inputs.
- Map behaviors to ATLAS techniques and tactics.
- Cover prompt injection, jailbreaks, model extraction, data poisoning, model backdoors, and ML supply-chain compromise.
- Surface technique IDs, rationale, and defensive context.

The embedded ATLAS corpus is versioned in the source so the mapping can be reviewed rather than treated as a black box.

### 3. Red-Team Intel
- Build an ATT&CK-oriented attack narrative.
- Visualize attack progression as a timeline.
- Estimate weaponization, stealth, privilege, and detection difficulty.
- Generate a structured intelligence report for investigation and review.

## Outputs

| Output | Purpose |
|---|---|
| Risk score | Fast triage |
| ATT&CK / ATLAS mappings | Common analyst language |
| IOC extraction | Investigation pivots |
| Attack timeline | Understand progression |
| Narrative | Human-readable explanation |
| PDF / JSON / TXT | Shareable evidence |

## Quick start

```bash
git clone https://github.com/Pyhroff/darkdecoder
cd darkdecoder
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set GROQ_API_KEY in .env
streamlit run app.py
```

The application can also run with its built-in samples for demonstration.

### API key boundary

DarkDecoder uses Groq for AI-assisted analysis. **Do not put API keys in source code or commit .env.** Treat submitted source code and generated reports as potentially sensitive.

## Built-in demonstrations

- PowerShell and Python malware-style inputs
- Webshell / cryptominer-style inputs
- Prompt injection and jailbreak scenarios
- Data poisoning and model-extraction scenarios
- ATT&CK-style red-team narratives

## Scope and limitations

DarkDecoder is an **AI-assisted triage tool**. It does not prove that an input is malicious, does not replace dynamic sandbox execution, and should not be treated as authoritative attribution. Framework mappings and generated narratives are analysis aids and should be validated against the underlying evidence.

AI-generated results can be incomplete or wrong. Do not execute suspicious samples merely because the tool labels them low risk.

## Related work

| Project | Role |
|---|---|
| **DarkDecoder** | Threat intelligence and framework mapping |
| [PromptStrike](https://github.com/Pyhroff/promptstrike) | Adversarial AI red teaming |
| [SOC PARALLAX](https://github.com/Pyhroff/soc-parallax) | Detection, correlation, and evidence-grounded SOC analysis |

## Development

```bash
pip install -r requirements.txt
streamlit run app.py
python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).