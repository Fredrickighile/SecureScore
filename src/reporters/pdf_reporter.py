"""
SecureScore PDF Reporter - Premium Report Generation
Dark, professional security assessment report
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from datetime import datetime
from pathlib import Path


# ── Colour palette ────────────────────────────────────────────────────────────
BG_DARK   = colors.HexColor('#070B14')
BG_CARD   = colors.HexColor('#0D1424')
BG_PANEL  = colors.HexColor('#111827')
BORDER    = colors.HexColor('#1E293B')
BLUE      = colors.HexColor('#3B82F6')
BLUE_DARK = colors.HexColor('#1D4ED8')
GREEN     = colors.HexColor('#22C55E')
YELLOW    = colors.HexColor('#F59E0B')
RED       = colors.HexColor('#EF4444')
PURPLE    = colors.HexColor('#8B5CF6')
TEXT      = colors.HexColor('#E2E8F0')
MUTED     = colors.HexColor('#64748B')
WHITE     = colors.white

SEVERITY_COLORS = {
    'CRITICAL': colors.HexColor('#EF4444'),
    'HIGH':     colors.HexColor('#F59E0B'),
    'MEDIUM':   colors.HexColor('#EAB308'),
    'LOW':      colors.HexColor('#22C55E'),
}

RISK_COLORS = {
    'CRITICAL': colors.HexColor('#EF4444'),
    'HIGH':     colors.HexColor('#F97316'),
    'MEDIUM':   colors.HexColor('#F59E0B'),
    'LOW':      colors.HexColor('#22C55E'),
}


# ── Canvas helpers ────────────────────────────────────────────────────────────
def draw_bg(c, doc):
    """Draw dark background and header bar on every page."""
    w, h = letter
    c.saveState()
    # Full-page dark background
    c.setFillColor(BG_DARK)
    c.rect(0, 0, w, h, fill=1, stroke=0)
    # Top accent bar
    c.setFillColor(BLUE)
    c.rect(0, h - 6, w, 6, fill=1, stroke=0)
    # Page number (skip page 1)
    if doc.page > 1:
        c.setFillColor(MUTED)
        c.setFont('Helvetica', 8)
        c.drawRightString(w - 0.5*inch, 0.35*inch, f'Page {doc.page}')
        c.setFillColor(BORDER)
        c.rect(0.5*inch, 0.5*inch, w - inch, 0.5, fill=1, stroke=0)
    c.restoreState()


def draw_cover_bg(c, doc):
    """Full dark cover with branded accent elements."""
    w, h = letter
    c.saveState()
    c.setFillColor(BG_DARK)
    c.rect(0, 0, w, h, fill=1, stroke=0)
    # Left accent strip
    c.setFillColor(BLUE)
    c.rect(0, 0, 4, h, fill=1, stroke=0)
    # Bottom accent
    c.setFillColor(BG_CARD)
    c.rect(0, 0, w, 1.2*inch, fill=1, stroke=0)
    c.setFillColor(BLUE)
    c.rect(0, 1.2*inch, w, 1, fill=1, stroke=0)
    # Subtle grid dots (decorative)
    c.setFillColor(colors.HexColor('#0F1A2E'))
    for x in range(0, int(w)+1, 20):
        for y in range(0, int(h)+1, 20):
            c.circle(x, y, 0.8, fill=1, stroke=0)
    c.restoreState()


class PDFReporter:

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        def add(name, **kw):
            if name not in self.styles:
                self.styles.add(ParagraphStyle(name=name, **kw))

        add('SSTitle',
            fontName='Helvetica-Bold', fontSize=32,
            textColor=WHITE, alignment=TA_LEFT,
            spaceAfter=8, leading=38)

        add('SSSubtitle',
            fontName='Helvetica', fontSize=13,
            textColor=MUTED, alignment=TA_LEFT,
            spaceAfter=4)

        add('SSSection',
            fontName='Helvetica-Bold', fontSize=13,
            textColor=BLUE, spaceBefore=20, spaceAfter=10)

        add('SSBody',
            fontName='Helvetica', fontSize=10,
            textColor=TEXT, leading=16, spaceAfter=6)

        add('SSMuted',
            fontName='Helvetica', fontSize=9,
            textColor=MUTED, leading=14)

        add('SSMono',
            fontName='Courier', fontSize=9,
            textColor=TEXT)

        add('SSLabel',
            fontName='Helvetica-Bold', fontSize=9,
            textColor=MUTED, spaceBefore=4)

    def generate(self, scan_results: dict, output_path: Path):
        doc = BaseDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=0.6*inch,
            leftMargin=0.6*inch,
            topMargin=0.7*inch,
            bottomMargin=0.7*inch,
        )

        # Page templates
        cover_frame = Frame(0, 0, letter[0], letter[1], leftPadding=0.8*inch,
                            rightPadding=0.6*inch, topPadding=0.8*inch, bottomPadding=1.5*inch)
        body_frame  = Frame(0.6*inch, 0.7*inch, letter[0]-1.2*inch, letter[1]-1.4*inch,
                            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

        doc.addPageTemplates([
            PageTemplate(id='Cover', frames=cover_frame, onPage=draw_cover_bg),
            PageTemplate(id='Body',  frames=body_frame,  onPage=draw_bg),
        ])

        story = []
        story.extend(self._cover(scan_results, doc))
        story.append(PageBreak())
        story.extend(self._executive_summary(scan_results))
        story.append(PageBreak())
        story.extend(self._vulnerabilities(scan_results))
        story.append(PageBreak())
        story.extend(self._ransomware_readiness(scan_results))
        story.extend(self._recommendations(scan_results))
        story.extend(self._footer_page())

        doc.build(story)
        print(f'[+] Premium PDF report saved: {output_path.name}')

    # ── Cover page ────────────────────────────────────────────────────────────
    def _cover(self, results, doc):
        els = []
        risk = results.get('overall_risk', {})
        rr   = results.get('ransomware_readiness', {})
        target    = results.get('target', 'Unknown')
        scan_time = results.get('scan_time', '')
        try:
            dt = datetime.fromisoformat(scan_time).strftime('%B %d, %Y  %I:%M %p')
        except Exception:
            dt = scan_time

        els.append(Spacer(1, 1.2*inch))
        els.append(Paragraph('SECURESCORE', ParagraphStyle('CoverBrand',
            fontName='Helvetica-Bold', fontSize=11, textColor=BLUE,
            letterSpacing=3, spaceAfter=16)))
        els.append(Paragraph('Security Assessment<br/>Report', ParagraphStyle('CoverTitle',
            fontName='Helvetica-Bold', fontSize=36, textColor=WHITE,
            leading=44, spaceAfter=24)))

        # Metadata table
        meta = [
            [_cell('Target', MUTED, 9), _cell(target, TEXT, 11, 'Courier-Bold')],
            [_cell('Scan date', MUTED, 9), _cell(dt, TEXT, 10)],
            [_cell('Report ID', MUTED, 9), _cell(f"SEC-{datetime.now().strftime('%Y%m%d-%H%M')}", TEXT, 10)],
        ]
        meta_t = Table(meta, colWidths=[1.2*inch, 4.5*inch])
        meta_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), BG_CARD),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [BG_CARD, BG_PANEL]),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 14),
            ('RIGHTPADDING', (0,0), (-1,-1), 14),
            ('LINEBELOW', (0,0), (-1,-2), 0.5, BORDER),
            ('ROUNDEDCORNERS', [6]),
        ]))
        els.append(meta_t)
        els.append(Spacer(1, 0.4*inch))

        # Score summary row on cover
        risk_score = min(100, risk.get('total_risk_score', 0))
        rr_score   = rr.get('readiness_score', 0)
        risk_level = risk.get('risk_level', 'UNKNOWN')
        rr_level   = rr.get('readiness_level', 'UNKNOWN')
        risk_col   = RISK_COLORS.get(risk_level, MUTED)
        rr_col     = GREEN if rr_score >= 70 else (YELLOW if rr_score >= 50 else RED)

        scores_data = [
            [
                _cell('OVERALL RISK SCORE', MUTED, 8),
                _cell(''),
                _cell('RANSOMWARE READINESS', MUTED, 8),
            ],
            [
                _cell(f'{risk_score}/100', risk_col, 28, 'Helvetica-Bold'),
                _cell(''),
                _cell(f'{rr_score}/100', rr_col, 28, 'Helvetica-Bold'),
            ],
            [
                _cell(risk_level, risk_col, 10, 'Helvetica-Bold'),
                _cell(''),
                _cell(rr_level, rr_col, 10, 'Helvetica-Bold'),
            ],
        ]
        scores_t = Table(scores_data, colWidths=[2.5*inch, 0.5*inch, 2.5*inch])
        scores_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), BG_CARD),
            ('BACKGROUND', (2,0), (2,-1), BG_CARD),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING', (0,0), (-1,-1), 16),
            ('LINEAFTER', (0,0), (0,-1), 2, risk_col),
            ('LINEBEFORE', (2,0), (2,-1), 2, rr_col),
        ]))
        els.append(scores_t)
        return els

    # ── Executive summary ─────────────────────────────────────────────────────
    def _executive_summary(self, results):
        els = [_next_template('Body')]
        risk = results.get('overall_risk', {})
        rr   = results.get('ransomware_readiness', {})

        els.append(Paragraph('Executive Summary', self.styles['SSSection']))
        els.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=12))

        risk_score = min(100, risk.get('total_risk_score', 0))
        risk_level = risk.get('risk_level', 'UNKNOWN')
        risk_col   = RISK_COLORS.get(risk_level, MUTED)
        total_v    = risk.get('total_vulnerabilities', 0)

        summary = (
            f"This security assessment of <b>{results.get('target', 'Unknown')}</b> identified "
            f"<b>{total_v} vulnerabilities</b> across network, SSL/TLS, email, and web application layers. "
            f"The overall risk score is <b>{risk_score}/100</b> ({risk_level} RISK). "
            f"Ransomware readiness score is <b>{rr.get('readiness_score', 0)}/100</b> "
            f"({rr.get('readiness_level', 'UNKNOWN')})."
        )
        els.append(Paragraph(summary, self.styles['SSBody']))
        els.append(Spacer(1, 14))

        # Stats row
        stats = [
            ['Risk Score', 'Readiness', 'Total Vulns', 'Critical', 'High', 'Medium'],
            [
                _cell(str(risk_score), risk_col, 18, 'Helvetica-Bold'),
                _cell(str(rr.get('readiness_score', 0)),
                      GREEN if rr.get('readiness_score',0)>=70 else YELLOW, 18, 'Helvetica-Bold'),
                _cell(str(total_v), TEXT, 18, 'Helvetica-Bold'),
                _cell(str(risk.get('critical_count', 0)), RED, 18, 'Helvetica-Bold'),
                _cell(str(risk.get('high_count', 0)), YELLOW, 18, 'Helvetica-Bold'),
                _cell(str(risk.get('medium_count', 0)), colors.HexColor('#EAB308'), 18, 'Helvetica-Bold'),
            ],
        ]
        col_w = (letter[0] - 1.2*inch) / 6
        stats_t = Table(stats, colWidths=[col_w]*6)
        stats_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_PANEL),
            ('BACKGROUND', (0,1), (-1,1), BG_CARD),
            ('TEXTCOLOR', (0,0), (-1,0), MUTED),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('LINEBELOW', (0,0), (-1,0), 0.5, BORDER),
            ('GRID', (0,0), (-1,-1), 0.5, BORDER),
            ('ROUNDEDCORNERS', [6]),
        ]))
        els.append(stats_t)
        els.append(Spacer(1, 20))

        # Ransomware readiness detail
        els.append(Paragraph('Ransomware Readiness Details', self.styles['SSSection']))
        els.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=12))

        rr_items = [
            ['Can Survive Attack',  'YES' if rr.get('can_survive_attack') else 'NO',
             GREEN if rr.get('can_survive_attack') else RED],
            ['Insurance Ready',     'YES' if rr.get('insurance_ready') else 'NO',
             GREEN if rr.get('insurance_ready') else RED],
            ['Estimated Recovery',  rr.get('estimated_recovery_time', 'Unknown'), TEXT],
        ]
        rr_data = [[_cell(r[0], MUTED, 9), _cell(r[1], r[2], 10, 'Helvetica-Bold')] for r in rr_items]
        rr_t = Table(rr_data, colWidths=[2.5*inch, 4.5*inch])
        rr_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), BG_CARD),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [BG_CARD, BG_PANEL]),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('LEFTPADDING', (0,0), (-1,-1), 14),
            ('LINEBELOW', (0,0), (-1,-2), 0.5, BORDER),
            ('ROUNDEDCORNERS', [6]),
        ]))
        els.append(rr_t)
        return els

    # ── All vulnerabilities ───────────────────────────────────────────────────
    def _vulnerabilities(self, results):
        els = [_next_template('Body')]
        risk  = results.get('overall_risk', {})
        vulns = risk.get('vulnerabilities', [])

        els.append(Paragraph('Detailed Findings', self.styles['SSSection']))
        els.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=12))

        if not vulns:
            els.append(Paragraph('No vulnerabilities detected.', self.styles['SSBody']))
            return els

        els.append(Paragraph(
            f'{len(vulns)} vulnerabilities found across all scan modules.',
            self.styles['SSBody']))
        els.append(Spacer(1, 10))

        for i, v in enumerate(vulns, 1):
            sev = v.get('severity', 'LOW')
            sev_col = SEVERITY_COLORS.get(sev, MUTED)

            # Header row
            header_data = [[
                _cell(f' {sev} ', sev_col, 8, 'Helvetica-Bold'),
                _cell(v.get('description', 'Unknown vulnerability'), WHITE, 10, 'Helvetica-Bold'),
            ]]
            header_t = Table(header_data, colWidths=[0.75*inch, 6.25*inch])
            header_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), BG_PANEL),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, BORDER),
                ('LINELEFT', (0,0), (0,-1), 3, sev_col),
            ]))
            els.append(header_t)

            # Detail rows
            detail_rows = []
            if v.get('impact'):
                detail_rows.append([_cell('Impact', MUTED, 8), _cell(v['impact'], TEXT, 9)])
            if v.get('recommendation'):
                detail_rows.append([_cell('Fix', BLUE, 8, 'Helvetica-Bold'), _cell(v['recommendation'], TEXT, 9)])
            if v.get('port'):
                detail_rows.append([_cell('Port', MUTED, 8), _cell(str(v['port']), TEXT, 9, 'Courier')])

            if detail_rows:
                detail_t = Table(detail_rows, colWidths=[0.75*inch, 6.25*inch])
                detail_t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), BG_CARD),
                    ('TOPPADDING', (0,0), (-1,-1), 7),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 7),
                    ('LEFTPADDING', (0,0), (-1,-1), 10),
                    ('LINEBELOW', (0,0), (-1,-2), 0.5, BORDER),
                    ('LINELEFT', (0,0), (0,-1), 3, sev_col),
                ]))
                els.append(detail_t)

            els.append(Spacer(1, 8))

        return els

    # ── Ransomware attack vectors ─────────────────────────────────────────────
    def _ransomware_readiness(self, results):
        els = []
        rr = results.get('ransomware_readiness', {})
        vectors = rr.get('attack_vectors', [])

        if not vectors:
            return els

        els.append(Paragraph('Ransomware Attack Vectors', self.styles['SSSection']))
        els.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=12))
        els.append(Paragraph(
            'The following attack vectors represent the primary ransomware entry points detected.',
            self.styles['SSBody']))
        els.append(Spacer(1, 10))

        for v in vectors:
            sev = v.get('severity', 'MEDIUM')
            sev_col = SEVERITY_COLORS.get(sev, MUTED)

            rows = [
                [_cell(f' {sev} ', sev_col, 8, 'Helvetica-Bold'),
                 _cell(v.get('vector', ''), WHITE, 10, 'Helvetica-Bold')],
                [_cell('Likelihood', MUTED, 8), _cell(v.get('likelihood', ''), TEXT, 9)],
                [_cell('Impact', MUTED, 8),     _cell(v.get('impact', ''), TEXT, 9)],
                [_cell('Fix', BLUE, 8, 'Helvetica-Bold'), _cell(v.get('fix', ''), TEXT, 9)],
            ]
            t = Table(rows, colWidths=[0.75*inch, 6.25*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), BG_PANEL),
                ('BACKGROUND', (0,1), (-1,-1), BG_CARD),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('LINEBELOW', (0,0), (-1,-2), 0.5, BORDER),
                ('LINELEFT', (0,0), (0,-1), 3, sev_col),
                ('ROUNDEDCORNERS', [6]),
            ]))
            els.append(t)
            els.append(Spacer(1, 10))

        return els

    # ── Recommendations ───────────────────────────────────────────────────────
    def _recommendations(self, results):
        els = []
        risk = results.get('overall_risk', {})
        recs = risk.get('recommendations', [])

        # Also pull from all scanner vulns if recommendations are sparse
        all_vulns = risk.get('vulnerabilities', [])
        all_recs = [v.get('recommendation') for v in all_vulns if v.get('recommendation')]
        # Merge unique
        seen = set(recs)
        for r in all_recs:
            if r not in seen:
                recs.append(r)
                seen.add(r)

        if not recs:
            return els

        els.append(Paragraph('Priority Recommendations', self.styles['SSSection']))
        els.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=12))

        for i, rec in enumerate(recs[:10], 1):
            row = [[
                _cell(str(i), BLUE, 11, 'Helvetica-Bold'),
                _cell(rec, TEXT, 9),
            ]]
            t = Table(row, colWidths=[0.4*inch, 6.6*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), BG_CARD),
                ('TOPPADDING', (0,0), (-1,-1), 9),
                ('BOTTOMPADDING', (0,0), (-1,-1), 9),
                ('LEFTPADDING', (0,0), (-1,-1), 12),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, BORDER),
                ('LINELEFT', (0,0), (0,-1), 2, BLUE),
            ]))
            els.append(t)
        els.append(Spacer(1, 20))
        return els

    # ── Last page footer ──────────────────────────────────────────────────────
    def _footer_page(self):
        els = []
        els.append(Spacer(1, 0.5*inch))
        els.append(HRFlowable(width='100%', thickness=0.5, color=BORDER, spaceAfter=16))
        els.append(Paragraph(
            'This report is confidential and intended solely for the recipient organisation. '
            'All findings are based on automated scanning and should be validated by a qualified '
            'security professional before remediation.',
            ParagraphStyle('Disc', fontName='Helvetica', fontSize=8,
                           textColor=MUTED, leading=13, alignment=TA_CENTER)
        ))
        els.append(Spacer(1, 8))
        els.append(Paragraph(
            'SecureScore  |  Built by Frederick Ighile  |  Ransomware Prevention for Canadian SMBs',
            ParagraphStyle('FooterBrand', fontName='Helvetica-Bold', fontSize=9,
                           textColor=MUTED, alignment=TA_CENTER)
        ))
        return els


# ── Helpers ───────────────────────────────────────────────────────────────────
def _cell(text, color=None, size=10, font='Helvetica'):
    style = ParagraphStyle('_c',
        fontName=font, fontSize=size,
        textColor=color or colors.HexColor('#E2E8F0'),
        leading=size * 1.4,
        wordWrap='CJK',
    )
    return Paragraph(str(text), style)


class _NextTemplate:
    """Flowable that switches page template."""
    def __init__(self, name):
        self.name = name
    def wrap(self, *args): return (0, 0)
    def draw(self): pass
    def __call__(self): return self

def _next_template(name):
    from reportlab.platypus import ActionFlowable
    return ActionFlowable(('nextPageTemplate', name))


# ── Test ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import json, sys
    from pathlib import Path

    sample = {
        "target": "example.com",
        "scan_time": datetime.now().isoformat(),
        "overall_risk": {
            "total_risk_score": 51,
            "risk_level": "HIGH",
            "total_vulnerabilities": 7,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 4,
            "low_count": 2,
            "vulnerabilities": [
                {"severity": "HIGH", "description": "Missing HSTS header",
                 "impact": "Vulnerable to SSL stripping attacks",
                 "recommendation": "Add Strict-Transport-Security header"},
                {"severity": "MEDIUM", "description": "No SPF record found",
                 "impact": "Attackers can spoof emails from your domain",
                 "recommendation": "Add SPF record to DNS"},
                {"severity": "MEDIUM", "description": "Missing X-Frame-Options",
                 "impact": "Vulnerable to clickjacking",
                 "recommendation": "Add X-Frame-Options: DENY"},
                {"severity": "LOW", "description": "Missing Referrer-Policy",
                 "impact": "May leak URL info",
                 "recommendation": "Add Referrer-Policy header"},
            ],
            "recommendations": ["Close RDP port 3389", "Add DMARC record"]
        },
        "ransomware_readiness": {
            "readiness_score": 90,
            "readiness_level": "WELL PROTECTED",
            "can_survive_attack": True,
            "insurance_ready": True,
            "estimated_recovery_time": "< 24 hours",
            "attack_vectors": [
                {"vector": "Missing SPF Record", "severity": "MEDIUM",
                 "likelihood": "Enables phishing", "impact": "Email spoofing",
                 "fix": "Add SPF record to DNS"}
            ]
        }
    }

    out = Path('test_report.pdf')
    PDFReporter().generate(sample, out)
    print(f'Test PDF: {out}')
