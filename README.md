# DarkDecoder

**Dual-Framework Cyber Threat Intelligence Platform**

> Paste suspicious code or AI inputs. Get structured threat-intelligence analysis mapped to MITRE ATT&CK and MITRE ATLAS.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama%203.3%2070B-F55036?style=flat)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20v4%2040%2B%20techniques-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![CI](https://github.com/Pyhroff/darkdecoder/actions/workflows/ci.yml/badge.svg)

---

## What Is DarkDecoder?

DarkDecoder combines two threat-framework lenses in one analysis workflow: **MITRE ATT&CK** for conventional adversary behavior and **MITRE ATLAS** for AI/ML attack patterns.

The current implementation uses an **embedded, versioned-in-code reference corpus**, rather than downloading the live MITRE catalogs at scan time. This makes analysis reproducible, but it also means framework coverage can become stale and should not be treated as a complete representation of the current ATT&CK or ATLAS knowledge bases.

The output combines model-assisted analysis with deterministic local static analysis and reporting: danger/risk scoring, technique mappings, IOC candidates, attack timelines, and remediation guidance. Results are analyst assistance, not authoritative threat attribution or certification.

---

## Three Analysis Modules

### Module 1 - Malware Scanner (MITRE ATT&CK)
- Deobfuscates base64, hex, eval chains, string concatenation
- Classifies malware type: Ransomware, Keylogger, Reverse Shell, Cryptominer, Webshell, and more
- Danger score 1–10 with full justification
- Maps to MITRE ATT&CK T-codes (T1059, T1547, T1486, etc.)
- Extracts IOCs: IPs, domains, URLs, file paths, registry keys, mutexes
- Plain English summary for non-technical stakeholders
- Actionable remediation steps

### Module 2 - AI Threat Analyzer (embedded ATLAS reference corpus)
- Maps against the ATLAS techniques encoded in `ai_analyzer.py`; this is a curated snapshot rather than the live ATLAS catalog
- Detects LLM-specific attacks: prompt injection (AML.T0051), jailbreak (AML.T0054), meta-prompt extraction (AML.T0058), plugin compromise (AML.T0057), LLM data leakage (AML.T0056)
- Flags training data poisoning, backdoor insertion, model extraction, membership inference
- Identifies ML supply chain attacks and surrogate model construction
- Dual-Framework mode: run both ATLAS + ATT&CK on the same input when code targets ML infrastructure

### Module 3 - Red Team Intel (ATT&CK Kill Chain)
- Full 10-phase ATT&CK kill chain visualization
- Weaponization score + stealth rating (1–10)
- Privilege escalation level: None → Local → Admin → Domain Admin → SYSTEM/Root
- Detection difficulty rating + CVSS vector string generation
- Named APT group / threat actor similarity matching
- Full attack narrative from an adversary perspective

---

## Features

| Feature | Details |
|---|---|
| File Upload | .py .js .php .ps1 .sh .bat .rb .go .cs .vbs (up to 200 MB) |
| Report Export | PDF · JSON · TXT - one click, all modules |
| Attack Timeline | Step-by-step progression with MITRE technique IDs |
| Session History | All scans logged with timestamps in sidebar |
| Hash Analysis | SHA256 + MD5 computed on every submission |
| Built-in Samples | Pre-loaded demo payloads including GCG suffix + Crescendo escalation |
| Zero Cost | Runs entirely on Groq's free tier - no credit card |
| ATLAS Depth | 40+ techniques, 13 tactics, tactic name shown per technique |

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Engine | Groq API - Llama 3.3 70B Versatile |
| Threat Framework 1 | MITRE ATT&CK reference corpus (embedded) |
| Threat Framework 2 | MITRE ATLAS reference corpus (embedded) |
| Backend | Python 3.10+ |
| Frontend | Streamlit |
| PDF Generation | fpdf2 |
| Environment | python-dotenv |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Pyhroff/darkdecoder
cd darkdecoder

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your free Groq API key
cp .env.example .env
# Open .env and set: GROQ_API_KEY=your_key_here

# 4. Run
streamlit run app.py
```

Get a **free Groq API key** at [console.groq.com](https://console.groq.com) - no credit card, 14,400 requests/day free tier.

---

## Built-in Demo Samples

| Module | Sample Payloads |
|---|---|
| Malware Scanner | PowerShell Dropper · Python Reverse Shell · JS Cryptominer · PHP Webshell · Ransomware Stub |
| AI Threat Analyzer | Prompt Injection · Data Poisoning · Model Extraction · Jailbreak · GCG Adversarial Suffix · Crescendo Escalation |
| Red Team Intel | Privilege Escalation · Lateral Movement · Defense Evasion · C2 Beacon |

---

## Why DarkDecoder?

| | DarkDecoder | VirusTotal | Traditional SIEMs |
|---|---|---|---|
| MITRE ATT&CK mapping |  | Partial |  (paid) |
| MITRE ATLAS (AI threats) |  40+ techniques |  |  |
| Red team kill chain |  |  |  |
| LLM-specific attacks |  |  |  |
| Free tier |  |  |  |
| Self-hostable |  |  |  |

---

## Project Structure

```
darkdecoder/
├── app.py                 # Main Streamlit UI (3 modules + dual-framework mode)
├── analyzer.py            # MITRE ATT&CK malware scanner
├── ai_analyzer.py         # MITRE ATLAS v4 AI threat detector (40+ techniques)
├── redteam_analyzer.py    # Red team kill chain analyzer
├── report_generator.py    # PDF report generation
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Related projects

DarkDecoder is one of three related AI-security projects:

| Project | Role | Frameworks |
|---|---|---|
| **DarkDecoder** | Threat intelligence - what is the attack? | MITRE ATT&CK + ATLAS |
| **[PromptStrike](https://github.com/Pyhroff/promptstrike)** | Active red teaming - can you jailbreak it? | PAIR · TAP · Crescendo · GCG |
| **[SOC PARALLAX](https://github.com/Pyhroff/soc-parallax)** | Behavioral defense - detect the attacker | Neo4j · LangGraph · Ollama |

---

## Interpretation and limitations

DarkDecoder is an analyst-assistance prototype, not a malware verdict engine or threat-attribution authority.

- LLM-generated classifications, scores, narratives, technique mappings, and CVSS vectors are hypotheses that should be validated by an analyst.
- MITRE mappings come from the embedded reference corpus shipped with this repository; they are not guaranteed to match the current live ATT&CK or ATLAS catalogs.
- Static analysis can miss dynamic behavior, generated code, native components, obfuscation, or behavior that only appears at runtime.
- Regex/static IOC extraction produces candidates; presence in source does not prove that an indicator is active, malicious, or contacted.
- A benign result does not prove that a sample is safe.
- Results should not be used as proof of compromise, compliance, attribution, or absence of vulnerabilities.
- Do not upload confidential source code, credentials, secrets, or regulated data to a third-party LLM provider.

For authoritative framework identifiers and current technique definitions, consult the live MITRE catalogs before operational use.

---

## License

MIT. See `LICENSE`.
