"""Client-friendly, tenant-scoped PDF reporting for the CyberGuardian dashboard."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether,
)

GLOSSARY = {
    "endpoint": "computer or device",
    "asset": "computer or device",
    "agent": "monitoring software",
    "heartbeat": "last check-in",
    "telemetry": "monitoring information",
    "malware": "harmful software",
    "ransomware": "software that locks files and demands payment",
    "exfiltration": "information being sent out without permission",
    "lateral movement": "an intruder moving between computers",
    "privilege escalation": "an attempt to gain higher access",
    "brute force": "repeated password guessing",
    "false positive": "an alert that may not represent a real threat",
    "detection": "security alert",
    "severity": "priority",
    "critical": "urgent",
    "high": "high priority",
    "medium": "needs review",
    "low": "informational",
    "containment": "limiting the spread of a suspected problem",
    "isolation": "temporarily disconnecting a device from the network",
    "quarantine": "temporarily restricting a device or file",
    "audit": "activity record",
    "idempotency": "duplicate-action protection",
    "tenant": "client organisation",
    "api": "secure connection between software systems",
    "offline": "not currently connected",
    "online": "connected",
    "pending": "waiting for review",
    "revoked": "disabled",
}

def _plain(value: Any, limit: int = 500) -> str:
    text = str(value if value is not None else "").replace("\x00", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]

def translate(value: Any) -> str:
    text = _plain(value, 2000)
    for term, meaning in sorted(GLOSSARY.items(), key=lambda item: -len(item[0])):
        text = re.sub(r"\b" + re.escape(term) + r"\b", meaning, text, flags=re.IGNORECASE)
    return text

def _items(payload: Any, key: str) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    value = payload.get(key, [])
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

def _number(payload: dict, *keys: str) -> int | str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return int(value)
    return "Not available"

def _severity_label(value: Any) -> str:
    raw = _plain(value, 40).lower()
    return {
        "critical": "Urgent review",
        "high": "High priority",
        "medium": "Review recommended",
        "low": "Informational",
    }.get(raw, "Priority not classified")

def build_client_pdf(snapshot: dict, *, tenant_id: str, generated_at: datetime | None = None) -> bytes:
    """Build an in-memory PDF; never writes client data to the dashboard filesystem."""
    if not tenant_id or str(snapshot.get("tenant_id") or "") != str(tenant_id):
        raise ValueError("report tenant identity is missing or does not match")
    generated_at = generated_at or datetime.now(timezone.utc)
    if generated_at.tzinfo is None:
        raise ValueError("report timestamp must include a timezone")

    risk = snapshot.get("risk") if isinstance(snapshot.get("risk"), dict) else {}
    fleet = snapshot.get("fleet") if isinstance(snapshot.get("fleet"), dict) else {}
    gate = snapshot.get("gate") if isinstance(snapshot.get("gate"), dict) else {}
    issues = _items(snapshot.get("issues"), "items")
    audit = _items(snapshot.get("audit"), "items")
    pending = _items(gate, "pending")
    assets = _number(risk, "total_assets", "assets_total")
    online = _number(risk, "online")
    if online == "Not available":
        online = _number(fleet, "online")
    detections = _number(risk, "open_detections", "detections_24h")
    mode = snapshot.get("client_mode")
    mode_text = "ON — security actions require human approval" if mode is True else (
        "OFF — review configuration before client use" if mode is False else "Not confirmed"
    )

    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CGTitle", parent=styles["Title"], fontSize=20, leading=24,
        textColor=colors.HexColor("#12304a"), alignment=TA_CENTER, spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="CGSub", parent=styles["Normal"], fontSize=9, leading=13,
        textColor=colors.HexColor("#526477"), alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="CGBody", parent=styles["BodyText"], fontSize=9, leading=13,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="CGSmall", parent=styles["BodyText"], fontSize=7.5, leading=10,
        textColor=colors.HexColor("#526477"),
    ))
    styles.add(ParagraphStyle(
        name="CGSection", parent=styles["Heading2"], fontSize=12, leading=15,
        textColor=colors.HexColor("#12304a"), spaceBefore=10, spaceAfter=6,
    ))
    doc = SimpleDocTemplate(
        output, pagesize=letter, rightMargin=.65*inch, leftMargin=.65*inch,
        topMargin=.65*inch, bottomMargin=.65*inch,
        title="CyberGuardian Client Security Report",
        author="TrinTech Digital Defense",
    )
    story = [
        Paragraph("CyberGuardian", styles["CGTitle"]),
        Paragraph("Client Security & Monitoring Report", styles["Heading2"]),
        Paragraph("Prepared by TrinTech Digital Defense", styles["CGSub"]),
        Spacer(1, 8),
        Paragraph(
            f"<b>Client reference:</b> {html.escape(_plain(tenant_id, 100))}<br/>"
            f"<b>Generated:</b> {generated_at.astimezone(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}<br/>"
            "<b>Coverage:</b> Current monitoring snapshot and the available recent activity summary",
            styles["CGBody"],
        ),
        Paragraph("At a glance", styles["CGSection"]),
    ]
    metrics = [
        ["Computers / devices", str(assets), "Currently connected", str(online)],
        ["Open security alerts", str(detections), "Items awaiting approval", str(len(pending))],
        ["Recent activity records reviewed", str(len(audit)), "Remembered issues", str(len(issues))],
    ]
    table = Table(metrics, colWidths=[1.55*inch, .8*inch, 1.55*inch, .8*inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#eef4f8")),
        ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor("#183247")),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("FONTNAME", (1,0), (1,-1), "Helvetica-Bold"),
        ("FONTNAME", (3,0), (3,-1), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), .4, colors.HexColor("#d5e0e8")),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story += [table, Paragraph("What this means", styles["CGSection"])]
    story.append(Paragraph(
        f"CyberGuardian currently lists <b>{html.escape(str(assets))}</b> computers or devices, "
        f"with <b>{html.escape(str(online))}</b> connected. It reports "
        f"<b>{html.escape(str(detections))}</b> open security alerts and "
        f"<b>{len(pending)}</b> items waiting for an operator decision. "
        "An alert is a reason to investigate; it is not, by itself, proof that a device was compromised.",
        styles["CGBody"],
    ))
    story += [
        Paragraph("Monitoring and response safeguards", styles["CGSection"]),
        Paragraph(f"<b>Human approval setting:</b> {html.escape(mode_text)}.", styles["CGBody"]),
        Paragraph(
            "CyberGuardian records security findings and operator decisions. Actions that could interrupt "
            "a device or its network connection should remain subject to an authorised person's review. "
            "This report does not claim that every alert is a confirmed incident.",
            styles["CGBody"],
        ),
        Paragraph("Items needing attention", styles["CGSection"]),
    ]
    if issues:
        for issue in issues[:15]:
            title = translate(issue.get("title") or issue.get("summary") or issue.get("description") or "Security issue recorded")
            severity = _severity_label(issue.get("severity") or issue.get("priority"))
            status = translate(issue.get("status") or "Recorded")
            story.append(Paragraph(
                f"<b>{html.escape(severity)}:</b> {html.escape(title)} "
                f"<font color='#526477'>({html.escape(status)})</font>",
                styles["CGBody"],
            ))
    else:
        story.append(Paragraph(
            "No remembered issues were returned by the monitoring service at the time this report was prepared. "
            "This does not prove that no security risks exist.",
            styles["CGBody"],
        ))
    story += [Paragraph("Recent activity", styles["CGSection"])]
    if audit:
        event_counts: dict[str, int] = {}
        for entry in audit:
            raw = _plain(entry.get("event") or entry.get("action") or "other", 80).lower()
            label = "Operator decisions" if any(x in raw for x in ("approve", "reject", "operator")) else (
                "Monitoring and system updates" if any(x in raw for x in ("agent", "heartbeat", "detection")) else
                "Other recorded activity"
            )
            event_counts[label] = event_counts.get(label, 0) + 1
        for label, count in sorted(event_counts.items()):
            story.append(Paragraph(f"• {label}: {count} record(s)", styles["CGBody"]))
    else:
        story.append(Paragraph("No recent activity records were returned.", styles["CGBody"]))
    weekly = _plain(snapshot.get("weekly_summary"), 5000)
    if weekly:
        story += [Paragraph("Recent monitoring summary", styles["CGSection"])]
        story.append(Paragraph(html.escape(translate(weekly)), styles["CGBody"]))
    story += [
        Paragraph("How to read this report", styles["CGSection"]),
        Paragraph(
            "A security alert means the system noticed activity worth checking. A high-priority alert should be "
            "reviewed promptly. A device shown as disconnected may simply be switched off or temporarily without "
            "network access. Your security operator can confirm the cause and advise on next steps.",
            styles["CGBody"],
        ),
        Paragraph("Data sources and report limitations", styles["CGSection"]),
        Paragraph(
            "This report was assembled from the authenticated dashboard's client-scoped monitoring summary, "
            "device list, approval queue, remembered-issue view, activity records and recent digest. "
            "Counts reflect the data returned by those services at report time; the activity view is limited "
            "to the latest records exposed by the service. Missing data is not treated as zero. "
            "This is an operational summary, not a certification, forensic conclusion or guarantee of security.",
            styles["CGSmall"],
        ),
        Spacer(1, 10),
        Paragraph(
            "Confidential — prepared for the identified client organisation. Handle and retain this report "
            "according to the client's approved data-retention policy.",
            styles["CGSmall"],
        ),
    ]

    def page_footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#d5e0e8"))
        canvas.line(.65*inch, .48*inch, 7.85*inch, .48*inch)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#526477"))
        canvas.drawString(.65*inch, .32*inch, "TrinTech Digital Defense | CyberGuardian")
        canvas.drawRightString(7.85*inch, .32*inch, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return output.getvalue()
