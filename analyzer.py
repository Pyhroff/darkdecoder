import anthropic
import os
import json
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are DarkDecoder, an elite malware reverse-engineering AI used by cybersecurity analysts.
When given suspicious, obfuscated, or potentially malicious code, you perform deep static analysis.

Always respond with ONLY valid JSON — no markdown, no explanation outside the JSON.

Required JSON structure:
{
  "deobfuscated_code": "cleaned/decoded version of the code, or 'N/A' if already readable",
  "classification": "specific malware type (e.g. Ransomware Dropper, Keylogger, Reverse Shell, Cryptominer, Spyware, Data Exfiltrator, Worm, Trojan, Rootkit, Benign)",
  "intent": "1-2 sentence description of exactly what this code attempts to do",
  "danger_score": <integer 1-10>,
  "danger_justification": "why this score was assigned",
  "plain_english_summary": "explain to a non-technical person what this code does and why it is dangerous",
  "mitre_techniques": [
    {"id": "TXXXX", "name": "Technique Name", "description": "how this code uses this technique"}
  ],
  "iocs": {
    "ips": [],
    "domains": [],
    "urls": [],
    "file_paths": [],
    "registry_keys": [],
    "mutex_names": [],
    "other": []
  },
  "remediation": [
    "Actionable step 1",
    "Actionable step 2",
    "Actionable step 3"
  ]
}

If code appears benign, set danger_score to 1-2 and classification to "Benign".
Always extract every IOC you can find, even if hardcoded strings that look like C2 infrastructure."""


def analyze_code(code: str) -> dict:
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze this code and return structured JSON:\n\n```\n{code}\n```"
            }
        ]
    )

    raw = response.content[0].text.strip()

    # Strip markdown code fences if Claude wraps in them
    if raw.startswith("```json"):
        raw = raw[7:]
    elif raw.startswith("```"):
        raw = raw[3:]
    if raw.endswith("```"):
        raw = raw[:-3]

    return json.loads(raw.strip())
