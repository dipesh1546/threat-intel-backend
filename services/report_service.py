"""
Report Service - Generates PDF, CSV, and JSON reports
"""

import json
import csv
import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

class ReportService:
    """Service for generating reports in various formats"""
    
    def generate_pdf(self, data: dict, report_type: str) -> bytes:
        """Generate PDF report"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#06b6d4'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        story.append(Paragraph("CyberNova TechGuard", title_style))
        story.append(Paragraph(f"Report Type: {report_type.upper()}", styles['Heading2']))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Spacer(1, 10))
        
        stats = data.get('stats', {})
        stats_data = [
            ['Metric', 'Value'],
            ['Active Threats', str(stats.get('active_threats', 0))],
            ['Critical Alerts', str(stats.get('critical_count', 0))],
            ['High Alerts', str(stats.get('high_count', 0))],
            ['Total IOCs', str(stats.get('total_iocs', 0))],
            ['Total CVEs', str(stats.get('total_cves', 0))],
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f2937')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#06b6d4')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#111827')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#f9fafb')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#374151'))
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        alerts = data.get('alerts', [])
        if alerts:
            story.append(Paragraph("Recent Threats", styles['Heading2']))
            story.append(Spacer(1, 10))
            for alert in alerts[:10]:
                story.append(Paragraph(f"<b>{alert.get('title', 'Threat Alert')}</b>", styles['Normal']))
                story.append(Paragraph(f"Severity: {alert.get('severity', 'Unknown')}", styles['Normal']))
                desc = alert.get('description', '')[:200]
                story.append(Paragraph(f"Description: {desc}", styles['Normal']))
                story.append(Spacer(1, 10))
        
        cves = data.get('cves', [])
        if cves:
            story.append(Paragraph("Critical CVEs", styles['Heading2']))
            story.append(Spacer(1, 10))
            cve_data = [['CVE ID', 'CVSS Score', 'Severity', 'Published']]
            for cve in cves[:10]:
                cve_data.append([
                    cve.get('cve_id', ''),
                    str(cve.get('cvss_score', 0)),
                    cve.get('severity', ''),
                    cve.get('published', '')
                ])
            cve_table = Table(cve_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.5*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f2937')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#06b6d4')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#374151'))
            ]))
            story.append(cve_table)
        
        story.append(Spacer(1, 30))
        story.append(Paragraph("This report was generated automatically by NepalThreat Intel Dashboard.", styles['Normal']))
        story.append(Paragraph("For questions, contact: info@cybernovatechguard.com", styles['Normal']))
        
        doc.build(story)
        return buffer.getvalue()
    
    def generate_csv(self, data: dict, report_type: str) -> str:
        """Generate CSV report"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        if report_type == 'ioc':
            writer.writerow(['ID', 'Value', 'Type', 'Severity', 'Confidence', 'Source', 'Tags', 'Last Seen'])
            iocs = data.get('iocs', {})
            ioc_list = iocs.get('urls', []) + iocs.get('ips', []) + iocs.get('domains', [])
            for ioc in ioc_list[:100]:
                writer.writerow([
                    ioc.get('id', ''),
                    ioc.get('value', ''),
                    ioc.get('type', ''),
                    ioc.get('severity', ''),
                    ioc.get('confidence', ''),
                    ioc.get('source', ''),
                    ', '.join(ioc.get('tags', [])),
                    ioc.get('last_seen', '')
                ])
        elif report_type == 'cve':
            writer.writerow(['CVE ID', 'CVSS Score', 'Severity', 'Description', 'Published', 'Affected Software'])
            for cve in data.get('cves', []):
                writer.writerow([
                    cve.get('cve_id', ''),
                    cve.get('cvss_score', ''),
                    cve.get('severity', ''),
                    cve.get('description', ''),
                    cve.get('published', ''),
                    ', '.join(cve.get('affected_software', []))
                ])
        else:
            writer.writerow(['Metric', 'Value'])
            stats = data.get('stats', {})
            for key, value in stats.items():
                writer.writerow([key, value])
        
        return output.getvalue()
    
    def generate_json(self, data: dict) -> str:
        """Generate JSON report"""
        return json.dumps(data, indent=2, default=str)


report_service = ReportService()
