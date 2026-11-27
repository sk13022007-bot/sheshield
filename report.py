import io
import os
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether,
)

# Use Windows' Nirmala UI font (covers English, Hindi, Kannada) if available.
FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
try:
    _fonts = r"C:\Windows\Fonts"
    pdfmetrics.registerFont(TTFont("Nirmala", os.path.join(_fonts, "Nirmala.ttf")))
    pdfmetrics.registerFont(TTFont("Nirmala-Bold", os.path.join(_fonts, "NirmalaB.ttf")))
    pdfmetrics.registerFontFamily(
        "Nirmala", normal="Nirmala", bold="Nirmala-Bold",
        italic="Nirmala", boldItalic="Nirmala-Bold")
    FONT = "Nirmala"
    FONT_BOLD = "Nirmala-Bold"
except Exception:
    pass

SEV_COLORS = {"none": "#2e9e5b", "low": "#d9a400",
              "medium": "#e07b00", "high": "#d62839"}
SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
BRAND = colors.HexColor("#7b3fbf")

title_style = ParagraphStyle("title", fontName=FONT_BOLD, fontSize=20,
                             textColor=BRAND, spaceAfter=2)
sub_style = ParagraphStyle("sub", fontName=FONT, fontSize=9,
                           textColor=colors.grey, spaceAfter=10)
h_style = ParagraphStyle("h", fontName=FONT_BOLD, fontSize=12.5,
                         textColor=BRAND, spaceBefore=12, spaceAfter=6)
body = ParagraphStyle("body", fontName=FONT, fontSize=9.5, leading=13)
small = ParagraphStyle("small", fontName=FONT, fontSize=8.5, leading=11,
                       textColor=colors.HexColor("#555555"))
ev_head = ParagraphStyle("evh", fontName=FONT_BOLD, fontSize=10,
                         spaceBefore=6, spaceAfter=3)
mono = ParagraphStyle("mono", fontName="Courier", fontSize=7, leading=9,
                      textColor=colors.HexColor("#555555"))


def _p(text, style):
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(FONT, 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(18 * mm, 10 * mm,
                      "SheShield complaint-support report. Automated analysis, not a legal verdict.")
    canvas.drawRightString(192 * mm, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def build_report(items, integrity, anchor=None):
    items = sorted(items or [], key=lambda x: x.get("id", 0))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=18 * mm,
        title="SheShield Complaint Report", author="SheShield")
    story = []

    story.append(Paragraph("SheShield", title_style))
    story.append(_p("Cyber-harassment evidence report. Generated "
                    + datetime.now().strftime("%d %b %Y, %H:%M"), sub_style))

    # ---- Summary
    highest = "none"
    for it in items:
        s = str(it.get("severity", "none")).lower()
        if SEV_RANK.get(s, 0) > SEV_RANK[highest]:
            highest = s

    if integrity and integrity.get("ok"):
        integ_text = ("PASSED: %s item(s) checked, no changes detected since saving."
                      % integrity.get("items_checked", len(items)))
        integ_color = "#2e9e5b"
    else:
        integ_text = ("FAILED: record #%s was modified after saving."
                      % (integrity or {}).get("tampered_at_id", "?"))
        integ_color = "#d62839"

    story.append(Paragraph("1. Summary", h_style))
    rows = [
        [_p("Evidence items", small), _p(len(items), body)],
        [_p("Highest severity", small),
         Paragraph('<font color="%s">%s</font>' % (SEV_COLORS[highest], highest.upper()), body)],
        [_p("Vault integrity", small),
         Paragraph('<font color="%s">%s</font>' % (integ_color, escape(integ_text)), body)],
    ]
    if items:
        rows.append([_p("Latest chain hash", small), _p(items[-1].get("hash", ""), mono)])
    if anchor:
        rows.append([_p("Blockchain anchor", small),
                     _p("Sepolia testnet tx: " + str(anchor), mono)])
    t = Table(rows, colWidths=[40 * mm, 134 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e6dff0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # ---- Timeline
    story.append(Paragraph("2. Timeline", h_style))
    if not items:
        story.append(_p("No evidence has been saved yet.", body))
    else:
        data = [[_p("#", small), _p("Saved at", small),
                 _p("Severity", small), _p("Score", small)]]
        for it in items:
            data.append([_p(it.get("id", ""), body), _p(it.get("created_at", ""), body),
                         _p(str(it.get("severity", "")).upper(), body),
                         _p(it.get("score", ""), body)])
        tl = Table(data, colWidths=[14 * mm, 70 * mm, 32 * mm, 25 * mm], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3ecfa")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e6dff0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i, it in enumerate(items, start=1):
            c = SEV_COLORS.get(str(it.get("severity", "none")).lower(), "#000000")
            style.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor(c)))
        tl.setStyle(TableStyle(style))
        story.append(tl)

    # ---- Evidence
    story.append(Paragraph("3. Evidence", h_style))
    for it in items:
        sev = str(it.get("severity", "none")).lower()
        head = "Evidence #%s  |  %s  |  score %s  |  saved %s" % (
            it.get("id", ""), sev.upper(), it.get("score", ""), it.get("created_at", ""))
        block = [
            _p(head, ev_head),
            _p(it.get("content", ""), body),
            Spacer(1, 3),
            _p("Hash: " + str(it.get("hash", "")), mono),
            _p("Previous hash: " + str(it.get("prev_hash", "")), mono),
            Spacer(1, 6),
        ]
        story.append(KeepTogether(block))

    # ---- Next steps
    story.append(Paragraph("4. Next steps", h_style))
    steps = [
        "Do not delete the original messages. Keep the original screenshots and note dates and times.",
        "Report online at the National Cyber Crime Reporting Portal: cybercrime.gov.in",
        "National Cyber Crime Helpline: 1930. Women Helpline: 181. Emergency (police): 112.",
        "Give this report to the police. They can request the owner details of the phone numbers and "
        "accounts listed above from the telecom operator or platform.",
        "Tell a trusted person. You do not have to handle this alone.",
    ]
    for s in steps:
        story.append(_p("- " + s, body))
        story.append(Spacer(1, 2))

    # ---- Notes
    story.append(Paragraph("5. Important notes", h_style))
    notes = [
        "Severity and scores are automated likelihoods, not legal conclusions.",
        "The integrity check shows the records have not been changed since they were saved. "
        "It does not prove who sent a message.",
        "Phone numbers and handles were read automatically from screenshots and may contain "
        "reading errors. Please verify them against the original images.",
        "This report contains no names of any accused person. SheShield does not identify "
        "who owns a number or account.",
    ]
    for n in notes:
        story.append(_p("- " + n, small))
        story.append(Spacer(1, 2))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()