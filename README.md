# 🕵️ DarkDecoder — AI-Powered Malicious Code Analysis Engine

> Paste suspicious code. Get instant threat intelligence. Powered by Claude AI.

Built for **Beyond Tomorrow Summit Hackathon 2026**.

## What it does

DarkDecoder takes obfuscated, weaponized, or suspicious code and produces structured threat intelligence in seconds:

- **Deobfuscation** — decodes base64, hex, string concatenation, eval chains
- **Intent Classification** — identifies malware type (Ransomware, Keylogger, Reverse Shell, etc.)
- **Danger Scoring** — 1–10 risk rating with justification
- **Plain English Summary** — explains the threat to non-technical stakeholders
- **MITRE ATT&CK Mapping** — maps behavior to framework techniques
- **IOC Extraction** — pulls IPs, domains, file paths, registry keys, mutexes
- **Remediation Steps** — actionable response guidance

## Stack

- **AI Engine**: Claude Sonnet 4.6 (Anthropic API)
- **Backend**: Python
- **Frontend**: Streamlit
- **Auth**: python-dotenv

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/Pyhroff/darkdecoder
cd darkdecoder

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your API key
echo "ANTHROPIC_API_KEY=your_key_here" > .env

# 4. Run
streamlit run app.py
```

## Demo

Three built-in sample snippets for live demonstration:
- PowerShell encoded dropper
- Python reverse shell
- JavaScript cryptominer

---

*DarkDecoder — Because malware doesn't explain itself.*
