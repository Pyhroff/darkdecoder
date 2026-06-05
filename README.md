# 💀 DarkDecoder — Dual-Framework Cyber Threat Intelligence Platform

> Paste suspicious code. Get instant threat intelligence in 20 seconds.

Built for **Beyond Tomorrow Summit Hackathon 2026** · [github.com/Pyhroff/darkdecoder](https://github.com/Pyhroff/darkdecoder)

---

## What It Does

DarkDecoder is a **dual-framework AI-powered threat intelligence platform** with three analysis modules:

### ⚠️ Module 1 — Malware Scanner (MITRE ATT&CK)
- Deobfuscates base64, hex, eval chains, string concatenation
- Classifies malware type: Ransomware, Keylogger, Reverse Shell, Cryptominer, etc.
- Danger score 1–10 with full justification
- Maps to MITRE ATT&CK techniques (T-codes)
- Extracts IOCs: IPs, domains, URLs, file paths, registry keys, mutexes
- Plain English summary for non-technical stakeholders
- Actionable remediation steps

### 🤖 Module 2 — AI Threat Analyzer (MITRE ATLAS)
- Detects prompt injection attacks against LLM systems
- Identifies jailbreak and safety guardrail bypass techniques
- Catches training data poisoning samples
- Flags model extraction query patterns
- Maps to MITRE ATLAS AML.TXXXX codes — the official AI threat framework

### 🔴 Module 3 — Red Team Intel (ATT&CK Kill Chain)
- 10-phase ATT&CK kill chain grid visualization
- Weaponization score + stealth rating (1–10)
- Privilege escalation level: None → Local → Admin → SYSTEM/Root
- Detection difficulty assessment
- Named APT group similarity matching
- CVSS vector string generation
- Full attack narrative from an APT perspective

---

## Features

| Feature | Details |
|---|---|
| File Upload | .py .js .php .ps1 .sh .bat .rb .go .cs .vbs |
| Report Export | PDF · JSON · TXT (one click) |
| Attack Timeline | Numbered progression with MITRE technique IDs |
| Session History | All scans logged with timestamps in sidebar |
| Hash Analysis | SHA256 + MD5 computed on every submission |
| Onboarding | Sample code buttons for instant demo |

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Engine | Groq API — Llama 3.3 70B (70B parameter LLM) |
| Threat Framework 1 | MITRE ATT&CK (Traditional threats) |
| Threat Framework 2 | MITRE ATLAS (AI/ML adversarial threats) |
| Backend | Python 3.10+ |
| Frontend | Streamlit |
| PDF Generation | fpdf2 |
| Environment | python-dotenv |

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/Pyhroff/darkdecoder
cd darkdecoder

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your API key
cp .env.example .env
# Edit .env and add your Groq API key

# 4. Run
streamlit run app.py
```

**Get a free Groq API key at [console.groq.com](https://console.groq.com)** — no credit card required. Free tier: 14,400 requests/day.

---

## Demo Samples (Built-in)

**Malware Scanner:** PowerShell Dropper · Python Reverse Shell · JS Cryptominer · PHP Webshell · Ransomware Stub

**AI Threat Analyzer:** Prompt Injection · Data Poisoning · Model Extraction · Jailbreak Attempt

**Red Team Intel:** Privilege Escalation · Lateral Movement · Defense Evasion · C2 Beacon

---

## Why DarkDecoder Is Different

- **Only tool** combining MITRE ATT&CK + MITRE ATLAS in a single platform
- **Explains WHY** code is dangerous, not just flags it
- **Red team perspective** — full kill chain analysis available free
- **AI-specific threat detection** — prompt injection, jailbreaks, data poisoning
- **Deployable for $0** — Groq free tier, no cloud infrastructure needed

---

*DarkDecoder — Because malware doesn't explain itself.*
