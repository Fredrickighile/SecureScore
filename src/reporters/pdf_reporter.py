"""
PDF Report Generator
Creates professional security assessment reports
"""
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
from pathlib import Path

class PDFReporter:
    """Generates professional PDF security reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()
    
    def _add_custom_styles(self):
        """Add custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Risk score style
        self.styles.add(ParagraphStyle(
            name='RiskScore',
            parent=self.styles['Normal'],
            fontSize=18,
            textColor=colors.HexColor('#d32f2f'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2196F3'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        ))
    
    def generate(self, scan_results: dict, output_path: Path):
        """
        Generate PDF report from scan results
        
        Args:
            scan_results: Complete scan results dict
            output_path: Path to save PDF file
        """
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        story = []
        
        # Add content sections
        story.extend(self._build_header(scan_results))
        story.extend(self._build_executive_summary(scan_results))
        story.append(PageBreak())
        story.extend(self._build_vulnerabilities_section(scan_results))
        story.append(PageBreak())
        story.extend(self._build_recommendations_section(scan_results))
        story.extend(self._build_footer())
        
        # Build PDF
        doc.build(story)
        print(f"[✓] PDF report generated: {output_path}")
    
    def _build_header(self, results: dict):
        """Build report header"""
        elements = []
        
        # Title
        title = Paragraph("SECURITY ASSESSMENT REPORT", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Report info table
        scan_time = datetime.fromisoformat(results['scan_time']).strftime('%B %d, %Y %I:%M %p')
        
        info_data = [
            ['Target:', results['target']],
            ['Scan Date:', scan_time],
            ['Report ID:', f"SEC-{datetime.now().strftime('%Y%m%d-%H%M')}"]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#555555')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 0.5*inch))
        
        return elements
    
    def _build_executive_summary(self, results: dict):
        """Build executive summary section"""
        elements = []
        risk = results['overall_risk']
        
        # Section header
        header = Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader'])
        elements.append(header)
        
        # Risk score box
        risk_color = self._get_risk_color(risk['risk_level'])
        risk_text = f"""
        <para align=center>
        <font size=48 color='{risk_color}'><b>{risk['total_risk_score']}/100</b></font><br/>
        <font size=18><b>{risk['risk_level']} RISK</b></font>
        </para>
        """
        elements.append(Paragraph(risk_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Vulnerability counts
        vuln_data = [
            ['Total Vulnerabilities', str(risk['total_vulnerabilities'])],
            ['Critical', str(risk['critical_count'])],
            ['High', str(risk['high_count'])],
            ['Medium', str(risk['medium_count'])]
        ]
        
        vuln_table = Table(vuln_data, colWidths=[3*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2196F3')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ]))
        
        elements.append(vuln_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Key findings
        summary_text = f"""
        This security assessment identified <b>{risk['total_vulnerabilities']} vulnerabilities</b> 
        across network, SSL/TLS, and email security configurations. 
        The overall risk score of <b>{risk['total_risk_score']}/100</b> indicates 
        a <b>{risk['risk_level']}</b> security posture.
        """
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        
        return elements
    
    def _build_vulnerabilities_section(self, results: dict):
        """Build detailed vulnerabilities section"""
        elements = []
        vulnerabilities = results['overall_risk']['vulnerabilities']
        
        header = Paragraph("DETAILED FINDINGS", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        if not vulnerabilities:
            elements.append(Paragraph("No vulnerabilities detected.", self.styles['Normal']))
            return elements
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # Vulnerability title
            severity_color = self._get_severity_color(vuln['severity'])
            title_text = f"""
            <font size=12><b>{i}. [{vuln['severity']}] {vuln['description']}</b></font>
            """
            elements.append(Paragraph(title_text, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Vulnerability details
            details_data = [
                ['Type:', vuln.get('type', 'N/A')],
                ['Impact:', vuln.get('impact', 'N/A')],
                ['Recommendation:', vuln.get('recommendation', 'N/A')]
            ]
            
            details_table = Table(details_data, colWidths=[1.5*inch, 4.5*inch])
            details_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            
            elements.append(details_table)
            elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_recommendations_section(self, results: dict):
        """Build recommendations section"""
        elements = []
        recommendations = results['overall_risk']['recommendations']
        
        header = Paragraph("PRIORITY RECOMMENDATIONS", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        if not recommendations:
            elements.append(Paragraph("No recommendations at this time.", self.styles['Normal']))
            return elements
        
        rec_text = "<br/>".join([f"{i}. {rec}" for i, rec in enumerate(recommendations, 1)])
        elements.append(Paragraph(rec_text, self.styles['Normal']))
        
        return elements
    
    def _build_footer(self):
        """Build report footer"""
        elements = []
        elements.append(Spacer(1, 0.5*inch))
        
        footer_text = """
        <para align=center>
        <font size=8 color='#666666'>
        Report generated by SecureScore - Automated Security Assessment Platform<br/>
        Created by Frederick Ighile | fredrick.ighile.dev@gmail.com<br/>
        This report is confidential and intended solely for the recipient organization.
        </font>
        </para>
        """
        elements.append(Paragraph(footer_text, self.styles['Normal']))
        
        return elements
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors_map = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#388e3c'
        }
        return colors_map.get(risk_level, '#000000')
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        return self._get_risk_color(severity)

# Test function
if __name__ == "__main__":
    import json
    from pathlib import Path
    
    # Load sample scan result
    reports_dir = Path(__file__).parent.parent.parent / "reports"
    sample_file = list(reports_dir.glob("*.json"))[0]
    
    with open(sample_file, 'r') as f:
        results = json.load(f)
    
    # Generate PDF
    reporter = PDFReporter()
    pdf_path = reports_dir / "sample_report.pdf"
    reporter.generate(results, pdf_path)
    print(f"Sample PDF generated: {pdf_path}")