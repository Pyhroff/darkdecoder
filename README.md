# 💀 DarkDecoder

**Dual-Framework Cyber Threat Intelligence Platform**

> Paste suspicious code. Get instant AI-powered threat intelligence in under 20 seconds — mapped to MITRE ATT&CK *and* MITRE ATLAS.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama%203.3%2070B-F55036?style=flat)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## What Is DarkDecoder?

DarkDecoder is the **only free tool** that combines two official cyber threat frameworks — **MITRE ATT&CK** for traditional malware and **MITRE ATLAS** for AI/ML adversarial threats — in a single platform.

Security analysts waste hours manually cross-referencing malicious code against threat databases. DarkDecoder does it in 20 seconds: paste code, get a full breakdown — danger score, technique mappings, IOCs, kill chain, remediation steps, and exportable reports.

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

### Module 2 — AI Threat Analyzer (MITRE ATLAS)
- Detects prompt injection attacks targeting LLM-based systems
- Identifies jailbreak and safety guardrail bypass techniques
- Flags training data poisoning and backdoor injection samples
- Catches model extraction and membership inference queries
- Maps directly to MITRE ATLAS AML.TXXXX codes — the official AI adversarial threat framework

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
| Built-in Samples | Pre-loaded demo payloads for instant testing |
| Zero Cost | Runs entirely on Groq's free tier — no credit card |

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Engine | Groq API — Llama 3.3 70B Versatile |
| Threat Framework 1 | MITRE ATT&CK v14 |
| Threat Framework 2 | MITRE ATLAS (AI/ML adversarial threats) |
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
| AI Threat Analyzer | Prompt Injection · Data Poisoning · Model Extraction · Jailbreak Attempt |
| Red Team Intel | Privilege Escalation · Lateral Movement · Defense Evasion · C2 Beacon |

---

## Why DarkDecoder?

| | DarkDecoder | VirusTotal | Traditional SIEMs |
|---|---|---|---|
| MITRE ATT&CK mapping | ✅ | Partial | ✅ (paid) |
| MITRE ATLAS (AI threats) | ✅ | ❌ | ❌ |
| Red team kill chain | ✅ | ❌ | ❌ |
| Free tier | ✅ | ✅ | ❌ |
| Self-hostable | ✅ | ❌ | ❌ |
| Explains WHY | ✅ | ❌ | ❌ |

---

## Project Structure

```
darkdecoder/
├── app.py                 # Main Streamlit UI
├── analyzer.py            # MITRE ATT&CK malware scanner
├── ai_analyzer.py         # MITRE ATLAS AI threat detector
├── redteam_analyzer.py    # Red team kill chain analyzer
├── report_generator.py    # PDF report generation
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## License

MIT License — free to use, modify, and deploy.

---

*DarkDecoder — Because malware doesn't explain itself.*
