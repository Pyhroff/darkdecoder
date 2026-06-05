import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are DarkDecoder, an elite malware reverse-engineering AI used by cybersecurity analysts.
When given suspicious, obfuscated, or potentially malicious code, you perform deep static analysis.

Always respond with ONLY valid JSON — no markdown, no explanation outside the JSON.

Required JSON structure:
{
  "deobfuscated_code": "cleaned/decoded version of the code, or 'N/A' if already readable",
  "classification": "specific malware type (e.g. Ransomware Dropper, Keylogger, Reverse Shell, Cryptominer, Spyware, Data Exfiltrator, Worm, Trojan, Rootkit, Benign)",
  "intent": "1-2 sentence description of exactly what this code attempts to do",
  "danger_score": 7,
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
  ],
  "attack_timeline": [
    {"step": 1, "phase": "Phase Name", "action": "What happens at this step", "technique_id": "TXXXX"},
    {"step": 2, "phase": "Phase Name", "action": "What happens next", "technique_id": "TXXXX"}
  ]
}

If code appears benign, set danger_score to 1 and classification to "Benign".
Always extract every IOC you can find."""


def _sanitize_input(code: str) -> str:
    """Strip any attempt to inject instructions into the analyzer prompt."""
    code = code[:15000]  # Hard cap at 15k chars
    return code

def _parse_json(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```json"):
        raw = raw[7:]
    elif raw.startswith("```"):
        raw = raw[3:]
    if raw.endswith("```"):
        raw = raw[:-3]
    return json.loads(raw.strip())

def analyze_code(code: str) -> dict:
    code = _sanitize_input(code)
    last_error = None

    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this code and return structured JSON:\n\n```\n{code}\n```"}
                ],
                temperature=0.2,
                max_tokens=4096,
                timeout=30,
            )
            raw = response.choices[0].message.content
            return _parse_json(raw)

        except json.JSONDecodeError as e:
            last_error = f"Response parsing error (attempt {attempt+1}/3): {e}"
            continue
        except Exception as e:
            err = str(e)
            if "rate_limit" in err.lower() or "429" in err:
                raise RuntimeError("Rate limit reached. Please wait 30 seconds and try again.")
            if "timeout" in err.lower() or "timed out" in err.lower():
                raise RuntimeError("Request timed out. Groq may be busy — please try again.")
            if "api_key" in err.lower() or "authentication" in err.lower():
                raise RuntimeError("Invalid API key. Please check your GROQ_API_KEY in the .env file.")
            last_error = err
            if attempt < 2:
                continue
            raise RuntimeError(f"Analysis failed after 3 attempts: {last_error}")

    raise RuntimeError(f"Analysis failed: {last_error}")
