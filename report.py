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
    _env_font = os.environ.get("SHESHIELD_PDF_FONT")  # path to a .ttf covering Hindi/Kannada (optional)
    if _env_font and os.path.exists(_env_font):
        pdfmetrics.registerFont(TTFont("EnvFont", _env_font))
        FONT = FONT_BOLD = "EnvFont"
        raise StopIteration
    _fonts = r"C:\Windows\Fonts"
    pdfmetrics.registerFont(TTFont("Nirmala", os.path.join(_fonts, "Nirmala.ttf")))
    pdfmetrics.registerFont(TTFont("Nirmala-Bold", os.path.join(_fonts, "NirmalaB.ttf")))
    pdfmetrics.registerFontFamily(
        "Nirmala", normal="Nirmala", bold="Nirmala-Bold",
        italic="Nirmala", boldItalic="Nirmala-Bold")
    FONT = "Nirmala"
    FONT_BOLD = "Nirmala-Bold"
except StopIteration:
    pass
except Exception:
    pass

SEV_COLORS = {"none": "#3E7A5E", "low": "#8A6414",
              "medium": "#A4501A", "high": "#A2222E"}
SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
BRAND = colors.HexColor("#3F1634")

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



CAT_LABEL = {
    "sextortion": "Sextortion", "blackmail_extortion": "Blackmail / extortion", "threat": "Threat of violence",
    "harassment_abuse": "Harassment / abuse", "cyberstalking_contact": "Cyberstalking / repeated contact",
    "impersonation": "Impersonation", "romance_scam": "Romance scam pattern", "financial_scam": "Financial scam pattern",
    "phishing": "Phishing pattern", "coercive_manipulation": "Coercive control", "benign": "No pattern found",
}
box_style = ParagraphStyle("box", fontName=FONT, fontSize=9.5, leading=13)
h3 = ParagraphStyle("h3", fontName=FONT_BOLD, fontSize=10, textColor=BRAND, spaceBefore=6, spaceAfter=3)


def _boxed(flowables, bg="#F7F1F4", border="#C98A9E"):
    t = Table([[flowables]], colWidths=[174 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
                           ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(border)),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return t


def _chain_state(anchor):
    """Honest blockchain wording. Only states we can actually support from stored data."""
    if not anchor:
        return "Not anchored. The fingerprint exists only in this vault."
    st = anchor.get("state") or "submitted"
    tx = anchor.get("tx_hash", "")
    net = "Sepolia test network"
    return {
        "submitted": f"Transaction submitted on the {net} ({tx}). Not yet confirmed by this report.",
        "confirmed": f"Transaction confirmed on the {net} ({tx}).",
        "verified": f"Fingerprint read back from the contract on the {net} and matched ({tx}).",
        "mismatch": f"Fingerprint on the {net} does NOT match the current vault fingerprint ({tx}). Records changed after anchoring.",
    }.get(st, f"Transaction recorded on the {net} ({tx}).")


def build_report(items, integrity, anchor=None, pathway=None, links=None):
    """anchor: tx hash string (legacy) or dict(tx_hash, state, ...). pathway: legal.pathway() dict. links: identifiers.link_records()."""
    if isinstance(anchor, str):
        anchor = {"tx_hash": anchor, "state": "submitted"}
    items = sorted(items or [], key=lambda x: x.get("id", 0))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=18 * mm,
        title="SheShield Complaint Report", author="SheShield")
    story = []
    story.append(Paragraph("SheShield", title_style))
    story.append(_p("Cyber-harassment evidence report. Generated " + datetime.now().strftime("%d %b %Y, %H:%M"), sub_style))

    highest, top_item = "none", None
    for it in items:
        s = str(it.get("severity", "none")).lower()
        if SEV_RANK.get(s, 0) > SEV_RANK[highest]:
            highest, top_item = s, it
    meta = (top_item or {}).get("meta") or {}
    cat = (pathway or {}).get("category") or meta.get("category") or "benign"

    if integrity and integrity.get("ok"):
        integ_text = "PASSED: %s item(s) checked, no changes detected since saving." % integrity.get("items_checked", len(items))
        integ_color = "#3E7A5E"
    else:
        integ_text = "FAILED: record #%s was modified after saving." % (integrity or {}).get("tampered_at_id", "?")
        integ_color = "#A2222E"

    # 1. Summary
    story.append(Paragraph("1. Incident summary", h_style))
    rows = [
        [_p("Evidence records", small), _p(len(items), body)],
        [_p("Main category (automated)", small), _p(CAT_LABEL.get(cat, cat), body)],
        [_p("Highest risk level", small), Paragraph('<font color="%s">%s</font>' % (SEV_COLORS[highest], highest.upper()), body)],
        [_p("Languages seen", small), _p(", ".join(sorted({(i.get("meta") or {}).get("language", "") for i in items} - {""})) or "-", body)],
        [_p("Vault integrity", small), Paragraph('<font color="%s">%s</font>' % (integ_color, escape(integ_text)), body)],
    ]
    if items:
        rows.append([_p("Latest chain hash", small), _p(items[-1].get("hash", ""), mono)])
    rows.append([_p("Blockchain", small), _p(_chain_state(anchor), body)])
    t = Table(rows, colWidths=[40 * mm, 134 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#E6DED7")),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(t)
    if top_item and meta.get("indicators"):
        story.append(Paragraph("Observed indicators in the highest-risk record (record #%s)" % top_item["id"], h3))
        for ind in meta["indicators"][:8]:
            story.append(_p("- " + str(ind.get("label", "")), body))

    # 2. Next steps and legal pathway (prominent)
    story.append(Paragraph("2. Your Next Steps \u2013 Reporting & Legal Pathway", h_style))
    if pathway:
        story.append(_boxed([_p(pathway.get("headline", ""), ParagraphStyle("hl", fontName=FONT_BOLD, fontSize=10.5, leading=14, textColor=BRAND)),
                             Spacer(1, 3), _p(pathway.get("disclaimer", ""), small)]))
        story.append(Paragraph("What to do now", h3))
        for i, st in enumerate(pathway.get("next_steps", []), 1):
            story.append(_p("%d. %s" % (i, st), body))
            story.append(Spacer(1, 2))
        story.append(Paragraph("Where to report", h3))
        ch = [[_p("Channel", small), _p("Use it for", small), _p("Contact", small)]]
        for c in pathway.get("channels", []):
            ch.append([_p(c.get("name", ""), body), _p(c.get("use_for", ""), small), _p(c.get("contact", ""), body)])
        ct = Table(ch, colWidths=[46 * mm, 80 * mm, 48 * mm], repeatRows=1)
        ct.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2EDE8")),
                                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E6DED7")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(ct)
        story.append(Spacer(1, 3))
        story.append(_p(pathway.get("note_1930", ""), small))
        provs = pathway.get("provisions", [])
        if provs:
            story.append(Paragraph("Provisions that may be relevant (potentially applicable, not a conclusion)", h3))
            story.append(_p("Each row says why it may be relevant and what must be true for it to apply. Whether any provision applies is decided by the police and courts, not by this report.", small))
            story.append(Spacer(1, 3))
            for p in provs:
                story.append(KeepTogether([
                    _p("%s \u2013 %s" % (p.get("ref", ""), p.get("title", "")), ev_head),
                    _p("Why it may be relevant: " + p.get("why_relevant", ""), body),
                    _p("Only applies if: " + p.get("applies_if", ""), small),
                    Spacer(1, 4)]))
        story.append(_p("Provision references last checked on %s. Verify current text at %s." % (pathway.get("checked_on", ""), pathway.get("verify_at", "")), small))
    else:
        story.append(_p("No category could be determined, so no provisions are listed. You can still report at cybercrime.gov.in (emergency: 112).", body))

    # 3. Related incidents
    if links and (links.get("groups") or links.get("clusters")):
        story.append(Paragraph("3. Repeated identifiers in this vault", h_style))
        for g in links.get("groups", []):
            story.append(_p("- %s (%s match): %s Records: %s." % (g.get("label", g.get("kind")), g.get("confidence", ""), g.get("message", ""),
                                                                  ", ".join("#%s" % i for i in g.get("record_ids", []))), body))
            for cau in g.get("cautions", [])[:2]:
                story.append(_p("   Caution: " + cau, small))
        story.append(_p(links.get("disclaimer", ""), small))

    # 4. Timeline
    story.append(Paragraph("4. Timeline", h_style))
    if not items:
        story.append(_p("No evidence has been saved yet.", body))
    else:
        data = [[_p("#", small), _p("Saved at", small), _p("Category", small), _p("Risk", small), _p("Score", small)]]
        for it in items:
            data.append([_p(it.get("id", ""), body), _p(it.get("created_at", ""), body),
                         _p(CAT_LABEL.get((it.get("meta") or {}).get("category", ""), "-"), body),
                         _p(str(it.get("severity", "")).upper(), body), _p(it.get("score", ""), body)])
        tl = Table(data, colWidths=[12 * mm, 52 * mm, 50 * mm, 24 * mm, 20 * mm], repeatRows=1)
        style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F2EDE8")),
                 ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E6DED7")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]
        for i, it in enumerate(items, start=1):
            c = SEV_COLORS.get(str(it.get("severity", "none")).lower(), "#000000")
            style.append(("TEXTCOLOR", (3, i), (3, i), colors.HexColor(c)))
        tl.setStyle(TableStyle(style))
        story.append(tl)

    # 5. Evidence
    story.append(Paragraph("5. Evidence and hashes", h_style))
    for it in items:
        sev = str(it.get("severity", "none")).lower()
        head = "Evidence #%s  |  %s  |  score %s  |  saved %s" % (it.get("id", ""), sev.upper(), it.get("score", ""), it.get("created_at", ""))
        m = it.get("meta") or {}
        block = [_p(head, ev_head), _p(it.get("content", ""), body)]
        if m.get("image_sha256"):
            block.append(_p("Screenshot SHA-256: " + m["image_sha256"], mono))
        if m.get("identifiers"):
            block.append(_p("Identifiers: " + ", ".join("%s=%s" % (i["kind"], i["value"]) for i in m["identifiers"]), small))
        block += [Spacer(1, 3), _p("Hash: " + str(it.get("hash", "")), mono), _p("Previous hash: " + str(it.get("prev_hash", "")), mono), Spacer(1, 6)]
        story.append(KeepTogether(block))

    # 6. Integrity and blockchain
    story.append(Paragraph("6. Integrity and blockchain status", h_style))
    story.append(_p("Vault check: " + integ_text, body))
    story.append(_p("Blockchain: " + _chain_state(anchor), body))
    story.append(_p("Anchoring proves that a fingerprint existed at a point in time. It does not prove who sent a message or that the content is true.", small))

    # 7. Notes
    story.append(Paragraph("7. Important notes", h_style))
    for n in [
        "Risk levels and categories are automated indicators about the wording of messages, not findings about any person.",
        "Statements here describe observed behaviour or an allegation. Nothing in this report says that anyone committed an offence; that is for the police and courts.",
        "This is general information, not legal advice. Consider speaking to a lawyer or a legal aid service.",
        "Phone numbers and handles read from screenshots may contain reading errors. Check them against the originals.",
        "SheShield does not identify who owns a number or account. The police can request that from the operator or platform.",
    ]:
        story.append(_p("- " + n, small))
        story.append(Spacer(1, 2))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
