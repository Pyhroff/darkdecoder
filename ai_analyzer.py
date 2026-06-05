import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

ATLAS_CORPUS = """
MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) — Full Technique Reference:

RECONNAISSANCE:
- AML.T0000 - ML Attack Staging: Preparing infrastructure and tools for AI-targeted attacks
- AML.T0047 - Search Victim's Publicly Available Research: Mining papers/repos for model architecture and training details
- AML.T0048 - Acquire Public ML Artifacts: Downloading pretrained models, datasets, embeddings for attack staging

RESOURCE DEVELOPMENT:
- AML.T0016 - Obtain Capabilities: Acquiring adversarial ML tools, attack frameworks, exploit scripts
- AML.T0017 - Develop Capabilities: Building custom adversarial tools, poisoning pipelines, proxy models
- AML.T0019 - Publish Poisoned Datasets: Releasing poisoned data through Hugging Face, GitHub, Kaggle to compromise downstream models

INITIAL ACCESS:
- AML.T0010 - ML Supply Chain Compromise: Attacking upstream ML dependencies, pretrained model repos, or training pipelines
- AML.T0046 - Spearphishing for Information: Targeting ML practitioners to extract model details, API keys, training configs
- AML.T0044 - Full ML Model Access: Gaining white-box access to weights and architecture through insider threat or breach

EXECUTION / MODEL ATTACKS:
- AML.T0051 - LLM Prompt Injection: Crafting inputs to hijack LLM behavior, override system prompts, exfiltrate data, execute unintended actions
- AML.T0054 - LLM Jailbreak: Bypassing LLM safety guardrails, content filters, RLHF alignment using roleplay, encoding, or adversarial prompts
- AML.T0043 - Craft Adversarial Data: Creating inputs to fool ML models at inference — image perturbations, text adversarial examples
- AML.T0020 - Poison Training Data: Injecting malicious samples into training datasets to embed backdoors or degrade performance
- AML.T0018 - Backdoor ML Model: Inserting hidden functionality triggered by specific inputs (trojan triggers)

COLLECTION / EXFILTRATION:
- AML.T0040 - ML Model Inference API Access: Systematic querying of model APIs to extract intelligence, reconstruct training data
- AML.T0024 - Exfiltration via ML Inference API: Using model outputs to leak PII or sensitive training data (membership inference)
- AML.T0005 - Create Proxy ML Model: Building a surrogate model by querying the target to enable transfer attacks and IP theft
- AML.T0056 - LLM Data Leakage: Extracting memorized training data through carefully crafted prompts
"""

SYSTEM_PROMPT = f"""You are ATLAS-GPT, an elite AI security analyst embedded in DarkDecoder.
You specialize in detecting adversarial threats against AI/ML systems using the MITRE ATLAS framework.

{ATLAS_CORPUS}

Analyze the given input — it may be a prompt, user message, system prompt, dataset sample, or model query log.
Identify adversarial patterns, attack techniques, and risks.

Always respond with ONLY valid JSON — no markdown, no text outside JSON.

Required JSON structure:
{{
  "input_type": "Prompt Injection | Jailbreak | Data Poisoning | Model Extraction | Membership Inference | Adversarial Input | Benign",
  "threat_level": <integer 1-10>,
  "threat_label": "CRITICAL | HIGH | MODERATE | LOW | BENIGN",
  "attack_summary": "2 sentence summary of what this input is attempting to do",
  "plain_english": "explain to a non-technical executive what this attack does and the business impact",
  "atlas_techniques": [
    {{"id": "AML.TXXXX", "name": "Technique Name", "confidence": "HIGH|MEDIUM|LOW", "description": "how this input uses this technique"}}
  ],
  "attack_goal": "Data Exfiltration | Model Manipulation | Safety Bypass | Reconnaissance | IP Theft | Denial of Service | Unknown",
  "target_system": "what type of AI system is being targeted",
  "evasion_indicators": ["indicator 1", "indicator 2"],
  "adversarial_patterns": ["specific pattern found 1", "specific pattern found 2"],
  "business_impact": "High | Medium | Low",
  "defenses": [
    "specific defensive measure 1",
    "specific defensive measure 2",
    "specific defensive measure 3"
  ]
}}
"""


def analyze_ai_threat(content: str, input_type_hint: str = "auto") -> dict:
    hint = f"\nInput type context: {input_type_hint}" if input_type_hint != "auto" else ""
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this for AI/ML adversarial threats:{hint}\n\n```\n{content}\n```"}
        ],
        temperature=0.1,
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
