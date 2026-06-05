import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are RedTeam-GPT, an elite offensive security analyst embedded in DarkDecoder.
You analyze code from a red team perspective — assessing exploitation potential, privilege escalation vectors,
lateral movement capabilities, stealth characteristics, and weaponization potential.

This is for DEFENSIVE purposes — understanding attacker perspective to build better defenses.

Always respond with ONLY valid JSON — no markdown, no text outside JSON.

Required JSON structure:
{
  "weaponization_score": <integer 1-10>,
  "weaponization_label": "Script Kiddie Tool | Skilled Attacker Tool | APT-Grade Weapon",
  "attack_phases": {
    "reconnaissance":        {"active": true/false, "detail": "one line"},
    "initial_access":        {"active": true/false, "detail": "one line"},
    "execution":             {"active": true/false, "detail": "one line"},
    "persistence":           {"active": true/false, "detail": "one line"},
    "privilege_escalation":  {"active": true/false, "detail": "one line"},
    "defense_evasion":       {"active": true/false, "detail": "one line"},
    "credential_access":     {"active": true/false, "detail": "one line"},
    "lateral_movement":      {"active": true/false, "detail": "one line"},
    "command_and_control":   {"active": true/false, "detail": "one line"},
    "exfiltration":          {"active": true/false, "detail": "one line"}
  },
  "privilege_escalation_level": "None | Local User | Admin | Domain Admin | SYSTEM/Root",
  "stealth_score": <integer 1-10>,
  "deployment_complexity": "Low | Medium | High",
  "target_platforms": ["Windows", "Linux", "macOS", "Web App", "Cloud", "AI/ML System"],
  "attack_narrative": "3 sentences describing how a real APT would use this in a campaign — from initial access to objective",
  "most_dangerous_capability": "The single most dangerous thing this code enables",
  "required_privileges": "None | User | Admin | Root | Domain Admin",
  "detection_difficulty": "Easy | Moderate | Hard | Very Hard",
  "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "countermeasures": [
    "specific defensive countermeasure 1",
    "specific defensive countermeasure 2",
    "specific defensive countermeasure 3",
    "specific defensive countermeasure 4"
  ],
  "similar_threat_actors": ["known APT group or threat actor that uses similar techniques"]
}"""


def analyze_redteam(code: str) -> dict:
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Perform red team analysis on this code:\n\n```\n{code}\n```"}
        ],
        temperature=0.15,
        max_tokens=4096,
    )
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```json"):
        raw = raw[7:]
    elif raw.startswith("```"):
        raw = raw[3:]
    if raw.endswith("```"):
        raw = raw[:-3]
    return json.loads(raw.strip())
