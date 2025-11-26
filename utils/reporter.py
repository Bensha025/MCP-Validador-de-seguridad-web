from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import datetime

# Genera un PDF simple con ReportLab.
def generate_pdf_report(data):
    file_name = f"report_{int(datetime.datetime.now().timestamp())}.pdf"

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(file_name)

    story = []

    # Título
    story.append(Paragraph("<b>Security Scan Report</b>", styles['Title']))
    story.append(Paragraph(f"URL: {data['url']}", styles['Normal']))
    story.append(Paragraph(f"Score: {data['score']}", styles['Normal']))

    # Encabezados de seguridad
    story.append(Paragraph("<b>Security Headers</b>", styles['Heading2']))
    for h, v in data['security_headers'].items():
        status = "OK" if v.get("present", False) else "Missing"
        story.append(Paragraph(f"{h}: {status}", styles['Normal']))

    # Cookies
    story.append(Paragraph("<b>Cookies</b>", styles['Heading2']))
    for c in data['cookies']['cookies']:
        story.append(
            Paragraph(f"{c['name']} — Risk: {c['risk']}", styles['Normal'])
        )

    # Construir PDF
    doc.build(story)
    return file_name
