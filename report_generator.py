from fpdf import FPDF
import datetime
import hashlib
import io


def _safe(text):
    if not isinstance(text, str):
        text = str(text)
    return text.encode('latin-1', 'replace').decode('latin-1')


class DarkDecoderPDF(FPDF):
    def __init__(self, module="Malware Scanner"):
        super().__init__()
        self.module = module
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        # Dark header bar
        self.set_fill_color(2, 11, 6)
        self.rect(0, 0, 210, 28, 'F')
        # Green accent line
        self.set_fill_color(0, 200, 50)
        self.rect(0, 28, 210, 1.5, 'F')
        # Title
        self.set_xy(12, 7)
        self.set_font('Courier', 'B', 16)
        self.set_text_color(0, 230, 60)
        self.cell(100, 8, 'DARKDECODER', ln=False)
        # Module badge
        self.set_font('Courier', '', 8)
        self.set_text_color(0, 150, 40)
        self.set_xy(12, 17)
        self.cell(0, 5, f'[ {self.module.upper()} ] -- THREAT INTELLIGENCE REPORT', ln=False)
        # Timestamp top right
        self.set_font('Courier', '', 7)
        self.set_text_color(0, 100, 30)
        self.set_xy(130, 11)
        self.cell(70, 5, datetime.datetime.now().strftime('%Y-%m-%d  %H:%M:%S UTC'), align='R')
        self.set_xy(10, 35)

    def footer(self):
        self.set_y(-14)
        self.set_fill_color(2, 11, 6)
        self.rect(0, self.get_y(), 210, 20, 'F')
        self.set_font('Courier', '', 7)
        self.set_text_color(0, 120, 35)
        self.cell(0, 10, f'DarkDecoder  |  Beyond Tomorrow Summit 2026  |  Page {self.page_no()}  |  FOR DEFENSIVE PURPOSES ONLY', align='C')

    def section_title(self, title):
        self.set_fill_color(5, 25, 10)
        self.set_draw_color(0, 180, 50)
        self.set_font('Courier', 'B', 9)
        self.set_text_color(0, 210, 55)
        self.rect(10, self.get_y(), 190, 8, 'FD')
        self.set_xy(13, self.get_y() + 1.5)
        self.cell(0, 5, f'// {title.upper()}')
        self.ln(10)

    def body_text(self, text, color=(200, 220, 200)):
        self.set_font('Helvetica', '', 9)
        self.set_text_color(*color)
        self.set_x(12)
        self.multi_cell(186, 5, _safe(text))
        self.ln(2)

    def key_val(self, key, val, key_color=(0, 180, 50), val_color=(220, 240, 220)):
        self.set_font('Courier', 'B', 8)
        self.set_text_color(*key_color)
        self.set_x(12)
        self.cell(45, 5, _safe(key + ':'), ln=False)
        self.set_font('Courier', '', 8)
        self.set_text_color(*val_color)
        self.multi_cell(145, 5, _safe(str(val)))

    def divider(self):
        self.set_draw_color(0, 80, 20)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def score_block(self, score, label, classification):
        score = int(score)
        if score >= 8:
            r, g, b = 200, 20, 20
        elif score >= 6:
            r, g, b = 200, 100, 0
        elif score >= 4:
            r, g, b = 180, 160, 0
        else:
            r, g, b = 0, 180, 50

        y = self.get_y()
        # Score box
        self.set_fill_color(r // 6, g // 6, b // 6)
        self.set_draw_color(r, g, b)
        self.rect(10, y, 55, 28, 'FD')
        self.set_font('Courier', 'B', 28)
        self.set_text_color(r, g, b)
        self.set_xy(10, y + 2)
        self.cell(55, 16, str(score), align='C')
        self.set_font('Courier', 'B', 7)
        self.set_xy(10, y + 19)
        self.cell(55, 5, '/ 10  THREAT SCORE', align='C')

        # Label + classification box
        self.set_fill_color(5, 18, 8)
        self.set_draw_color(r, g, b)
        self.rect(70, y, 130, 28, 'FD')
        self.set_font('Courier', 'B', 13)
        self.set_text_color(r, g, b)
        self.set_xy(74, y + 4)
        self.cell(120, 8, _safe(label))
        self.set_font('Courier', '', 9)
        self.set_text_color(180, 220, 180)
        self.set_xy(74, y + 14)
        self.cell(120, 6, _safe(f'Classification: {classification}'))

        self.set_xy(10, y + 32)

    def ioc_table(self, iocs):
        labels = {"ips": "IP Address", "domains": "Domain", "urls": "URL",
                  "file_paths": "File Path", "registry_keys": "Registry Key",
                  "mutex_names": "Mutex", "other": "Other"}
        has_iocs = False
        for key, label in labels.items():
            items = iocs.get(key, [])
            if items:
                has_iocs = True
                self.set_font('Courier', 'B', 7)
                self.set_text_color(0, 160, 40)
                self.set_x(12)
                self.cell(35, 5, label.upper(), ln=False)
                self.set_font('Courier', '', 8)
                self.set_text_color(255, 140, 50)
                self.multi_cell(155, 5, _safe('  |  '.join(items)))
        if not has_iocs:
            self.body_text('No indicators of compromise extracted.', (120, 140, 120))

    def timeline_section(self, timeline):
        if not timeline:
            return
        self.section_title('ATTACK TIMELINE')
        for i, step in enumerate(timeline):
            step_num = step.get('step', i + 1)
            phase = step.get('phase', 'Unknown Phase')
            action = step.get('action', '')
            tid = step.get('technique_id', '')

            # Step number circle (simulated with a filled rect)
            y = self.get_y()
            self.set_fill_color(0, 180, 50)
            self.rect(12, y, 8, 7, 'F')
            self.set_font('Courier', 'B', 7)
            self.set_text_color(0, 0, 0)
            self.set_xy(12, y + 0.5)
            self.cell(8, 5, str(step_num), align='C')

            # Phase name
            self.set_font('Courier', 'B', 8)
            self.set_text_color(0, 210, 55)
            self.set_xy(23, y)
            self.cell(50, 4, _safe(phase), ln=False)

            # Technique badge
            if tid:
                self.set_font('Courier', 'B', 7)
                self.set_text_color(80, 140, 255)
                self.cell(30, 4, _safe(f'[{tid}]'), ln=False)

            # Action
            self.set_font('Helvetica', '', 8)
            self.set_text_color(180, 220, 180)
            self.set_xy(23, y + 5)
            self.multi_cell(177, 4, _safe(action))

            # Connector line (except last)
            if i < len(timeline) - 1:
                self.set_draw_color(0, 80, 20)
                cx = 16
                ly = self.get_y()
                self.line(cx, ly, cx, ly + 3)
                self.ln(3)
            else:
                self.ln(3)


def generate_malware_pdf(code_input: str, result: dict) -> bytes:
    pdf = DarkDecoderPDF("Malware Scanner")
    pdf.add_page()

    sha256 = hashlib.sha256(code_input.encode()).hexdigest()
    md5 = hashlib.md5(code_input.encode()).hexdigest()
    score = result.get('danger_score', 0)
    label_map = {range(8, 11): "CRITICAL THREAT", range(6, 8): "HIGH RISK",
                 range(4, 6): "MODERATE", range(0, 4): "LOW / CLEAN"}
    label = next((v for r, v in label_map.items() if score in r), "UNKNOWN")

    # Score block
    pdf.score_block(score, label, result.get('classification', 'Unknown'))
    pdf.ln(4)

    # Hashes
    pdf.section_title('FILE METADATA')
    pdf.key_val('SHA256', sha256)
    pdf.key_val('MD5', md5)
    pdf.key_val('Size', f'{len(code_input.encode())} bytes')
    pdf.key_val('Danger Score', f'{score}/10 — {result.get("danger_justification", "")}')
    pdf.divider()

    # Intent
    pdf.section_title('DETECTED INTENT')
    pdf.body_text(result.get('intent', 'N/A'))
    pdf.divider()

    # Plain English
    pdf.section_title('EXECUTIVE THREAT BRIEF')
    pdf.body_text(result.get('plain_english_summary', 'N/A'))
    pdf.divider()

    # Deobfuscated
    deob = result.get('deobfuscated_code', 'N/A')
    if deob and deob != 'N/A':
        pdf.section_title('DEOBFUSCATED CODE')
        pdf.set_font('Courier', '', 7)
        pdf.set_fill_color(3, 15, 8)
        pdf.set_draw_color(0, 80, 20)
        pdf.set_text_color(0, 200, 50)
        pdf.set_x(12)
        pdf.multi_cell(186, 4, _safe(deob[:1200]), border=1, fill=True)
        pdf.ln(4)
        pdf.divider()

    # MITRE ATT&CK
    pdf.section_title('MITRE ATT&CK TECHNIQUE MAPPING')
    for t in result.get('mitre_techniques', []):
        pdf.set_font('Courier', 'B', 8)
        pdf.set_text_color(80, 140, 255)
        pdf.set_x(12)
        pdf.cell(22, 5, _safe(t.get('id', '')), ln=False)
        pdf.set_text_color(200, 230, 200)
        pdf.cell(60, 5, _safe(t.get('name', '')), ln=False)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(140, 170, 140)
        pdf.multi_cell(108, 5, _safe(t.get('description', '')))
    pdf.divider()

    # IOCs
    pdf.section_title('INDICATORS OF COMPROMISE (IOCs)')
    pdf.ioc_table(result.get('iocs', {}))
    pdf.divider()

    # Timeline
    pdf.timeline_section(result.get('attack_timeline', []))
    if result.get('attack_timeline'):
        pdf.divider()

    # Remediation
    pdf.section_title('REMEDIATION PROTOCOL')
    for i, step in enumerate(result.get('remediation', []), 1):
        pdf.set_font('Courier', 'B', 8)
        pdf.set_text_color(0, 200, 50)
        pdf.set_x(12)
        pdf.cell(10, 5, f'{i:02d}.', ln=False)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(200, 230, 200)
        pdf.multi_cell(180, 5, _safe(step))

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def generate_redteam_pdf(code_input: str, result: dict) -> bytes:
    pdf = DarkDecoderPDF("Red Team Intel")
    pdf.add_page()

    score = result.get('weaponization_score', 0)
    label_map = {range(8, 11): "APT-GRADE WEAPON", range(6, 8): "HIGH THREAT",
                 range(4, 6): "MODERATE", range(0, 4): "LOW RISK"}
    label = next((v for r, v in label_map.items() if score in r), "UNKNOWN")

    pdf.score_block(score, label, result.get('weaponization_label', 'Unknown'))
    pdf.ln(4)

    pdf.section_title('WEAPONIZATION PROFILE')
    pdf.key_val('Priv Escalation', result.get('privilege_escalation_level', 'Unknown'))
    pdf.key_val('Stealth Score', f'{result.get("stealth_score", 0)}/10')
    pdf.key_val('Detection Diff', result.get('detection_difficulty', 'Unknown'))
    pdf.key_val('Deployment', result.get('deployment_complexity', 'Unknown'))
    pdf.key_val('Required Privs', result.get('required_privileges', 'Unknown'))
    pdf.key_val('Target Platforms', ', '.join(result.get('target_platforms', [])))
    pdf.key_val('Similar Actors', ', '.join(result.get('similar_threat_actors', [])))
    pdf.key_val('CVSS Vector', result.get('cvss_vector', 'N/A'))
    pdf.divider()

    pdf.section_title('MOST DANGEROUS CAPABILITY')
    pdf.body_text(result.get('most_dangerous_capability', 'N/A'), (255, 180, 180))
    pdf.divider()

    pdf.section_title('ATTACK NARRATIVE (APT CAMPAIGN PERSPECTIVE)')
    pdf.body_text(result.get('attack_narrative', 'N/A'))
    pdf.divider()

    # Kill chain phases
    pdf.section_title('ATT&CK KILL CHAIN — ACTIVE PHASES')
    phases = result.get('attack_phases', {})
    phase_order = ['reconnaissance', 'initial_access', 'execution', 'persistence',
                   'privilege_escalation', 'defense_evasion', 'credential_access',
                   'lateral_movement', 'command_and_control', 'exfiltration']
    for p in phase_order:
        data = phases.get(p, {})
        active = data.get('active', False)
        display = p.replace('_', ' ').upper()
        pdf.set_fill_color(30, 5, 5 if active else 5, )
        pdf.set_draw_color(180, 20, 20 if active else 0, )
        pdf.set_x(12)
        col = (220, 60, 60) if active else (60, 100, 60)
        indicator = '[ACTIVE]' if active else '[------]'
        pdf.set_font('Courier', 'B', 8)
        pdf.set_text_color(*col)
        pdf.cell(20, 5, indicator, ln=False)
        pdf.cell(45, 5, display, ln=False)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(180, 200, 180)
        pdf.multi_cell(125, 5, _safe(data.get('detail', '')))
    pdf.divider()

    pdf.timeline_section(result.get('attack_timeline', []))
    if result.get('attack_timeline'):
        pdf.divider()

    pdf.section_title('DEFENSIVE COUNTERMEASURES')
    for i, c in enumerate(result.get('countermeasures', []), 1):
        pdf.set_font('Courier', 'B', 8)
        pdf.set_text_color(0, 200, 50)
        pdf.set_x(12)
        pdf.cell(10, 5, f'{i:02d}.', ln=False)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(200, 230, 200)
        pdf.multi_cell(180, 5, _safe(c))

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def generate_ai_pdf(content_input: str, result: dict) -> bytes:
    pdf = DarkDecoderPDF("AI Threat Analyzer — MITRE ATLAS")
    pdf.add_page()

    score = result.get('threat_level', 0)
    label_map = {range(8, 11): "CRITICAL AI THREAT", range(6, 8): "HIGH RISK",
                 range(4, 6): "MODERATE", range(0, 4): "LOW / BENIGN"}
    label = next((v for r, v in label_map.items() if score in r), "UNKNOWN")

    pdf.score_block(score, label, result.get('input_type', 'Unknown'))
    pdf.ln(4)

    pdf.section_title('ATTACK PROFILE')
    pdf.key_val('Attack Goal', result.get('attack_goal', 'Unknown'))
    pdf.key_val('Target System', result.get('target_system', 'Unknown'))
    pdf.key_val('Business Impact', result.get('business_impact', 'Unknown'))
    pdf.divider()

    pdf.section_title('ATTACK SUMMARY')
    pdf.body_text(result.get('attack_summary', 'N/A'))
    pdf.divider()

    pdf.section_title('EXECUTIVE BRIEF')
    pdf.body_text(result.get('plain_english', 'N/A'))
    pdf.divider()

    pdf.section_title('MITRE ATLAS TECHNIQUE MAPPING')
    for t in result.get('atlas_techniques', []):
        conf = t.get('confidence', '?')
        conf_col = (220, 60, 60) if conf == 'HIGH' else (220, 140, 0) if conf == 'MEDIUM' else (200, 200, 0)
        pdf.set_font('Courier', 'B', 8)
        pdf.set_text_color(80, 140, 255)
        pdf.set_x(12)
        pdf.cell(24, 5, _safe(t.get('id', '')), ln=False)
        pdf.set_text_color(*conf_col)
        pdf.cell(18, 5, _safe(f'[{conf}]'), ln=False)
        pdf.set_text_color(200, 230, 200)
        pdf.cell(55, 5, _safe(t.get('name', '')), ln=False)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(140, 170, 140)
        pdf.multi_cell(93, 5, _safe(t.get('description', '')))
    pdf.divider()

    pdf.section_title('ADVERSARIAL PATTERNS DETECTED')
    for p in result.get('adversarial_patterns', []):
        pdf.set_font('Courier', '', 8)
        pdf.set_text_color(255, 140, 50)
        pdf.set_x(14)
        pdf.multi_cell(184, 5, _safe(f'> {p}'))
    pdf.divider()

    pdf.section_title('DEFENSIVE COUNTERMEASURES')
    for i, d in enumerate(result.get('defenses', []), 1):
        pdf.set_font('Courier', 'B', 8)
        pdf.set_text_color(0, 200, 50)
        pdf.set_x(12)
        pdf.cell(10, 5, f'{i:02d}.', ln=False)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(200, 230, 200)
        pdf.multi_cell(180, 5, _safe(d))

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()
