import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Full MITRE ATLAS v4 technique reference — 40+ techniques across 13 tactics
ATLAS_CORPUS = """
MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) v4
Complete Technique Reference — 13 Tactics, 40+ Techniques

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: RECONNAISSANCE (AML.TA0002)
Adversary gathers information about the target AI system to plan the attack.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0047 - Search Victim's Publicly Available Research:
  Mining academic papers, GitHub repos, HuggingFace model cards, and blog posts to infer
  model architecture, training data, hyperparameters, and potential vulnerabilities.

- AML.T0048 - Acquire Public ML Artifacts:
  Downloading pretrained model weights, public datasets, embeddings from HuggingFace,
  TensorFlow Hub, or Kaggle as a foundation for developing transfer attacks.

- AML.T0036 - Active Scanning:
  Systematically probing a deployed ML API by sending carefully crafted inputs and
  observing outputs to reverse-engineer model architecture, decision boundaries, and
  confidence thresholds without white-box access.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: RESOURCE DEVELOPMENT (AML.TA0004)
Adversary builds capabilities, infrastructure, or tools for AI-targeted attacks.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0016 - Obtain Capabilities:
  Acquiring adversarial ML tools (Foolbox, ART, TextFooler, AutoAttack), exploit
  frameworks, pretrained attack models, or adversarial example generators.

- AML.T0017 - Develop Capabilities:
  Building custom adversarial tools — poisoning pipelines, proxy surrogate models,
  gradient-based attack scripts (GCG, PGD, FGSM), or jailbreak automation frameworks.

- AML.T0019 - Publish Poisoned Datasets:
  Uploading poisoned training data or malicious model weights to public repositories
  (HuggingFace Hub, Kaggle, GitHub) to compromise downstream users via the ML supply chain.

- AML.T0000 - ML Attack Staging:
  Setting up infrastructure and preparing all attack components — surrogate models,
  adversarial examples, poisoned datasets — before targeting the victim system.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: INITIAL ACCESS (AML.TA0005)
Adversary gains access to the target ML system or its supply chain.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0010 - ML Supply Chain Compromise:
  Attacking upstream ML dependencies — pretrained model repos, training data pipelines,
  ML libraries — so that the compromised artifact is incorporated into the victim's system
  without their knowledge. Analogous to software supply chain attacks.

- AML.T0046 - Spearphishing for Information:
  Targeting ML practitioners via tailored phishing to extract model architectures,
  API keys, training configurations, proprietary dataset details, or system access.

- AML.T0012 - Valid Accounts:
  Using stolen or compromised credentials to access ML platforms, MLOps tools
  (MLflow, Weights & Biases, SageMaker), or model serving infrastructure.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: ML MODEL ACCESS (AML.TA0006)
Adversary achieves different levels of access to the target ML model.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0044 - Full ML Model Access (White-Box):
  Obtaining complete access to model weights, architecture, gradients, and training code.
  Enables the most powerful attacks — GCG, PGD, C&W. Achieved via insider threat,
  breach of model storage, or leaked checkpoint files.

- AML.T0040 - ML Model Inference API Access (Black-Box):
  Query-only access to a deployed model API. Enables black-box attacks — PAIR, TAP,
  Crescendo, HopSkipJump — that rely solely on output observations.

- AML.T0041 - ML Model Limited Access (Gray-Box):
  Partial access — output probabilities/logits available but not gradients or weights.
  Enables score-based attacks more powerful than pure decision-based black-box methods.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: EXECUTION (AML.TA0007)
Adversary runs malicious code or inputs against the ML system.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0051 - LLM Prompt Injection:
  Crafting inputs that hijack LLM behavior, override system prompts, exfiltrate
  conversation context, or execute unintended tool calls. Includes direct injection
  (user-controlled input) and indirect injection (data retrieved by the model from
  external sources — emails, web pages, documents).

- AML.T0054 - LLM Jailbreak:
  Bypassing LLM safety guardrails, RLHF alignment, and content filters using
  roleplay personas (DAN, ALEX), encoding tricks (base64, pig Latin, cipher),
  hypothetical framing, adversarial suffixes (GCG), or multi-turn escalation (Crescendo).

- AML.T0057 - LLM Plugin Compromise:
  Attacking through LLM tool/plugin integrations — manipulating function call outputs,
  injecting via plugin-retrieved content, or abusing tool execution permissions to
  perform unauthorized actions in connected systems.

- AML.T0043 - Craft Adversarial Data:
  Creating perturbed inputs imperceptible to humans but causing misclassification —
  adversarial images (FGSM, PGD, C&W), adversarial text (TextFooler, BERT-Attack),
  or adversarial audio (CommanderSong).

- AML.T0020 - Poison Training Data:
  Injecting malicious samples into training datasets to embed backdoor triggers,
  degrade model performance on specific inputs, or bias the model toward attacker-
  desired behaviors. Effective when the adversary controls any portion of training data.

- AML.T0018 - Backdoor ML Model:
  Inserting hidden functionality triggered only by a specific input pattern (trigger).
  The model behaves normally on clean inputs but misbehaves when the trigger appears.
  Achievable via data poisoning, model surgery, or supply chain compromise.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: PERSISTENCE (AML.TA0008)
Adversary maintains access to the AI system across updates or reboots.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0011 - User Execution:
  Tricking ML practitioners into running malicious code — poisoned Jupyter notebooks,
  malicious training scripts, or trojanized ML utility packages.

- AML.T0021 - Establish Accounts:
  Creating legitimate-looking accounts on ML platforms (HuggingFace, Kaggle, MLflow)
  to publish poisoned models or datasets that persist independently of victim infrastructure.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: ML ATTACK STAGING (AML.TA0009)
Adversary prepares and refines the attack before deploying against the target.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0005 - Create Proxy ML Model:
  Building a surrogate model by querying the target to enable white-box attacks
  on a local copy — then transferring the adversarial examples to the real target.
  Used to bypass black-box limitations for gradient-based attacks.

- AML.T0042 - Verify Attack:
  Testing adversarial examples or poisoned data against a local copy or shadow model
  before deploying against the real target, to maximize success rate and minimize
  detection footprint.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: DEFENSE EVASION (AML.TA0010)
Adversary avoids detection by ML-based security systems.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0031 - Evade ML Model:
  Crafting inputs specifically designed to fool ML-based security detectors —
  adversarial malware binaries, obfuscated payloads, adversarial network traffic —
  so the attacker's activity is classified as benign by security ML models.

- AML.T0015 - Evade ML Model — Influence Bias:
  Subtly manipulating the data distribution seen by a continuously-learning model
  to gradually shift its decision boundaries over time without triggering anomaly detection.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: DISCOVERY (AML.TA0011)
Adversary enumerates ML assets, data, and infrastructure.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0053 - Discover ML Artifacts:
  Enumerating model files, training datasets, feature stores, experiment logs,
  and MLOps configuration within a compromised environment to understand the
  full scope of ML infrastructure for targeting.

- AML.T0058 - LLM Meta-Prompt Extraction:
  Systematically probing an LLM to extract its hidden system prompt or
  configuration instructions through carefully crafted queries, repetition attacks,
  or encoding tricks. Enables targeted follow-up jailbreaks and prompt injection.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: COLLECTION (AML.TA0012)
Adversary harvests data, model outputs, or intellectual property.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0035 - ML Artifact Collection:
  Gathering model weights, training scripts, hyperparameter logs, and
  experiment data from breached MLOps systems, cloud storage, or exposed endpoints.

- AML.T0037 - Data from Information Repositories:
  Extracting training datasets, feature engineering pipelines, or labeled
  annotation data from internal ML data stores.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: EXFILTRATION (AML.TA0014)
Adversary extracts model intelligence, memorized data, or IP.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0024 - Exfiltration via ML Inference API:
  Using the model's API outputs as a covert channel to leak memorized training data,
  PII, or other sensitive information embedded in model weights — via membership
  inference, model inversion, or data extraction attacks.

- AML.T0056 - LLM Data Leakage:
  Extracting memorized verbatim training data (PII, source code, copyrighted text)
  from large language models through carefully crafted prompt completions.
  Exploits the LLM's tendency to reproduce training data near its training distribution.

- AML.T0025 - Exfiltrate Model Weights:
  Directly stealing model weights through API-based model extraction — repeatedly
  querying to reconstruct a functionally equivalent model for IP theft or offline attack.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TACTIC: IMPACT (AML.TA0015)
Adversary degrades, destroys, or weaponizes the AI system.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- AML.T0029 - Deny ML Model Classification:
  Causing the model to fail on valid inputs by overwhelming it with adversarial
  examples, degrading its performance to the point of operational unavailability,
  or triggering error states that cascade across dependent systems.

- AML.T0034 - Cost Harvesting:
  Sending crafted inputs that maximize compute cost on inference infrastructure —
  exploiting slow-input vulnerabilities in transformer attention or forcing maximum
  token generation — to increase the victim's cloud compute bill.

- AML.T0048.001 - Compromise ML Model Integrity:
  Subtly modifying a deployed model's weights or outputs to introduce systematic
  biases, degrade accuracy on specific subpopulations, or make it produce
  misleading results without the operator detecting the compromise.
"""

SYSTEM_PROMPT = f"""You are ATLAS-GPT, an elite AI security analyst embedded in DarkDecoder.
You specialize in detecting adversarial threats against AI/ML systems using the full MITRE ATLAS v4 framework.

{ATLAS_CORPUS}

Analyze the given input — it may be a prompt, user message, system prompt, dataset sample, model query log,
or code involving ML systems. Identify all adversarial patterns, attack techniques, and risk signals.

IMPORTANT: Use ONLY the AML.TXXXX technique IDs listed above. Never invent technique IDs.
Map each finding to the most specific applicable technique.

Always respond with ONLY valid JSON — no markdown, no text outside JSON.

Required JSON structure:
{{
  "input_type": "Prompt Injection | Jailbreak | Data Poisoning | Model Extraction | Membership Inference | Adversarial Input | Supply Chain Attack | Meta-Prompt Extraction | Plugin Compromise | Benign",
  "threat_level": <integer 1-10>,
  "threat_label": "CRITICAL | HIGH | MODERATE | LOW | BENIGN",
  "attack_summary": "2 sentence summary of what this input is attempting to do and which tactic it falls under",
  "plain_english": "explain to a non-technical executive what this attack does and the business impact in 3-4 sentences",
  "atlas_techniques": [
    {{"id": "AML.TXXXX", "tactic": "Tactic Name", "name": "Technique Name", "confidence": "HIGH|MEDIUM|LOW", "description": "exactly how this input or code uses this technique"}}
  ],
  "attack_goal": "Data Exfiltration | Model Manipulation | Safety Bypass | Reconnaissance | IP Theft | Denial of Service | System Prompt Extraction | Plugin Abuse | Unknown",
  "target_system": "specific AI system type being targeted (e.g. Production LLM API, ML Training Pipeline, Content Moderation Model)",
  "evasion_indicators": ["specific evasion signal 1", "specific evasion signal 2"],
  "adversarial_patterns": ["specific pattern found verbatim or paraphrased from input"],
  "business_impact": "High | Medium | Low",
  "defenses": [
    "specific defensive measure referencing the detected technique",
    "specific defensive measure 2",
    "specific defensive measure 3",
    "specific defensive measure 4"
  ]
}}
"""


def analyze_ai_threat(content: str, input_type_hint: str = "auto") -> dict:
    content = content[:15000]
    hint = f"\nInput type context: {input_type_hint}" if input_type_hint != "auto" else ""
    last_error = None

    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this for AI/ML adversarial threats using MITRE ATLAS:{hint}\n\n```\n{content}\n```"}
                ],
                temperature=0.1,
                max_tokens=4096,
                timeout=30,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```json"):
                raw = raw[7:]
            elif raw.startswith("```"):
                raw = raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3]
            return json.loads(raw.strip())

        except json.JSONDecodeError:
            last_error = "Response parsing error"
            continue
        except Exception as e:
            err = str(e)
            if "rate_limit" in err.lower() or "429" in err:
                raise RuntimeError("Rate limit reached. Please wait 30 seconds and try again.")
            if "timeout" in err.lower():
                raise RuntimeError("Request timed out. Please try again.")
            if "api_key" in err.lower() or "authentication" in err.lower():
                raise RuntimeError("Invalid API key. Check your GROQ_API_KEY in .env file.")
            last_error = err
            if attempt < 2:
                continue
            raise RuntimeError(f"Analysis failed: {last_error}")

    raise RuntimeError(f"Analysis failed after retries: {last_error}")
