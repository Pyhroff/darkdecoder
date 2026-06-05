# 💀 DarkDecoder — Dual-Framework Cyber Threat Intelligence Platform

> Paste suspicious code. Get instant threat intelligence. Powered by Groq AI.

Built for **Beyond Tomorrow Summit Hackathon 2026**.

---

## What it does

DarkDecoder is a dual-framework AI-powered threat intelligence platform with three analysis modules:

### ⚠️ Malware Scanner — MITRE ATT&CK
- **Deobfuscation** — decodes base64, hex, eval chains, string concatenation
- **Intent Classification** — Ransomware, Keylogger, Reverse Shell, Cryptominer, etc.
- **Danger Scoring** — 1–10 risk rating with justification
- **MITRE ATT&CK Mapping** — maps behavior to official framework techniques
- **IOC Extraction** — IPs, domains, URLs, file paths, registry keys, mutexes
- **Plain English Summary** — explains the threat to non-technical stakeholders
- **Remediation Steps** — actionable defensive guidance

### 🤖 AI Threat Analyzer — MITRE ATLAS
- **Prompt Injection Detection** — identifies LLM hijacking attempts
- **Jailbreak Analysis** — detects safety guardrail bypass techniques
- **Data Poisoning Detection** — spots malicious training data samples
- **Model Extraction Detection** — identifies model stealing query patterns
- **ATLAS Technique Mapping** — maps to AML.TXXXX framework codes

### 🔴 Red Team Intel — Kill Chain
- **Weaponization Scoring** — Script Kiddie vs APT-Grade assessment
- **Kill Chain Grid** — 10-phase ATT&CK grid showing active attack phases
- **Privilege Escalation Analysis** — None → Local → Admin → SYSTEM/Root
- **Stealth & Detection Scoring** — how hard to detect this in the wild
- **Attack Narrative** — how a real APT would use this in a campaign
- **CVSS Vector** — standard vulnerability scoring string
- **APT Group Similarity** — named threat actors using similar techniques

---

## Stack

- **AI Engine**: Llama 3.3 70B (Groq API)
- **Frameworks**: MITRE ATT&CK + MITRE ATLAS
- **Backend**: Python
- **Frontend**: Streamlit
- **PDF Generation**: fpdf2
- **Auth**: python-dotenv

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/Pyhroff/darkdecoder
cd darkdecoder

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your API key
echo "GROQ_API_KEY=your_key_here" > .env

# 4. Run
streamlit run app.py
```

Get a free Groq API key at **console.groq.com** — no credit card required.

---

## Features

| Feature | Module |
|---|---|
| Malware deobfuscation | Malware Scanner |
| MITRE ATT&CK mapping | Malware Scanner |
| IOC extraction | Malware Scanner |
| Prompt injection detection | AI Threat Analyzer |
| MITRE ATLAS mapping | AI Threat Analyzer |
| Kill chain visualization | Red Team Intel |
| Attack timeline | All modules |
| File upload (.py .js .php .ps1 .sh) | All modules |
| PDF / JSON / TXT report export | All modules |
| Scan history + session stats | Sidebar |
| SHA256 / MD5 hash analysis | Malware Scanner |

---

## Demo Samples

**Malware Scanner:**
- PowerShell encoded dropper
- Python reverse shell
- JavaScript cryptominer
- PHP webshell
- Ransomware stub

**AI Threat Analyzer:**
- Prompt injection attack
- Data poisoning sample
- Model extraction attempt
- Jailbreak attempt

**Red Team Intel:**
- Privilege escalation
- Lateral movement
- Defense evasion
- C2 beacon

---

*DarkDecoder — Because malware doesn't explain itself.*
