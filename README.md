# 💀 DarkDecoder

**Dual-Framework Cyber Threat Intelligence Platform**

> Paste suspicious code or AI inputs. Get instant threat intelligence mapped to MITRE ATT&CK *and* MITRE ATLAS in under 20 seconds.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama%203.3%2070B-F55036?style=flat)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20v4%2040%2B%20techniques-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![CI](https://github.com/Pyhroff/darkdecoder/actions/workflows/ci.yml/badge.svg)

---

## What Is DarkDecoder?

DarkDecoder is the **only free tool** that combines two official cyber threat frameworks — **MITRE ATT&CK** for traditional malware and **MITRE ATLAS** for AI/ML adversarial threats — in a single platform.

Security analysts waste hours manually cross-referencing malicious code against threat databases. DarkDecoder does it in 20 seconds: paste code or a suspicious prompt, get a full breakdown — danger score, technique mappings, IOCs, kill chain, remediation steps, and exportable reports.

**MITRE ATLAS coverage: 40+ techniques across 13 tactics** — including all LLM-specific techniques (prompt injection, jailbreak, meta-prompt extraction, plugin compromise, LLM data leakage).

---

## Three Analysis Modules

### Module 1 — Malware Scanner (MITRE ATT&CK)
- Deobfuscates base64, hex, eval chains, string concatenation
- Classifies malware type: Ransomware, Keylogger, Reverse Shell, Cryptominer, Webshell, and more
- Danger score 1–10 with full justification
- Maps to MITRE ATT&CK T-codes (T1059, T1547, T1486, etc.)
- Extracts IOCs: IPs, domains, URLs, file paths, registry keys, mutexes
- Plain English summary for non-technical stakeholders
- Actionable remediation steps

### Module 2 — AI Threat Analyzer (MITRE ATLAS v4)
- **40+ ATLAS techniques** across all 13 tactics: Reconnaissance, Resource Development, Initial Access, ML Model Access, Execution, Persistence, ML Attack Staging, Defense Evasion, Discovery, Collection, Exfiltration, and Impact
- Detects LLM-specific attacks: prompt injection (AML.T0051), jailbreak (AML.T0054), meta-prompt extraction (AML.T0058), plugin compromise (AML.T0057), LLM data leakage (AML.T0056)
- Flags training data poisoning, backdoor insertion, model extraction, membership inference
- Identifies ML supply chain attacks and surrogate model construction
- Dual-Framework mode: run both ATLAS + ATT&CK on the same input when code targets ML infrastructure

### Module 3 — Red Team Intel (ATT&CK Kill Chain)
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
| Report Export | PDF · JSON · TXT — one click, all modules |
| Attack Timeline | Step-by-step progression with MITRE technique IDs |
| Session History | All scans logged with timestamps in sidebar |
| Hash Analysis | SHA256 + MD5 computed on every submission |
| Built-in Samples | Pre-loaded demo payloads including GCG suffix + Crescendo escalation |
| Zero Cost | Runs entirely on Groq's free tier — no credit card |
| ATLAS Depth | 40+ techniques, 13 tactics, tactic name shown per technique |

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Engine | Groq API — Llama 3.3 70B Versatile |
| Threat Framework 1 | MITRE ATT&CK v14 |
| Threat Framework 2 | MITRE ATLAS v4 (AI/ML adversarial threats) |
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

Get a **free Groq API key** at [console.groq.com](https://console.groq.com) — no credit card, 14,400 requests/day free tier.

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
| MITRE ATT&CK mapping | ✅ | Partial | ✅ (paid) |
| MITRE ATLAS (AI threats) | ✅ 40+ techniques | ❌ | ❌ |
| Red team kill chain | ✅ | ❌ | ❌ |
| LLM-specific attacks | ✅ | ❌ | ❌ |
| Free tier | ✅ | ✅ | ❌ |
| Self-hostable | ✅ | ❌ | ❌ |

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

## Security Portfolio

DarkDecoder is part of a three-project AI security portfolio:

| Project | Role | Frameworks |
|---|---|---|
| **DarkDecoder** | Threat intelligence — what is the attack? | MITRE ATT&CK + ATLAS |
| **[PromptStrike](https://github.com/Pyhroff/promptstrike)** | Active red teaming — can you jailbreak it? | PAIR · TAP · Crescendo · GCG |
| **[SOC PARALLAX](https://github.com/Pyhroff/soc-parallax)** | Behavioral defense — detect the attacker | Neo4j · LangGraph · Ollama |

---

## License

MIT License — free to use, modify, and deploy.

---

*DarkDecoder — Because malware doesn't explain itself.*
