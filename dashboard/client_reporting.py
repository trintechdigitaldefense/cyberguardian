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

def build_client_pdf(snapshot: dict, *, tenant_id: str, generated_at: datetime | None = None, report_period: dict | None = None) -> bytes:
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
    period_start = period_end = None
    if report_period is not None:
        if not isinstance(report_period, dict) or report_period.get("timezone") != "UTC" or report_period.get("boundary") != "[start, end)":
            raise ValueError("historical report period semantics are invalid")
        try:
            period_start = datetime.fromisoformat(str(report_period["start"]).replace("Z", "+00:00"))
            period_end = datetime.fromisoformat(str(report_period["end"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("historical report period is invalid") from exc
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValueError("historical report period must be timezone-aware and increasing")
        period_start = period_start.astimezone(timezone.utc)
        period_end = period_end.astimezone(timezone.utc)
        seen_ids = set()
        for entry in audit:
            source_id = str(entry.get("source_record_id") or "")
            if not source_id or source_id in seen_ids:
                raise ValueError("historical audit source IDs are missing or duplicated")
            seen_ids.add(source_id)
            if str(entry.get("tenant_id") or "") != str(tenant_id):
                raise ValueError("historical audit record tenant identity is missing or mismatched")
            try:
                event_time = datetime.fromisoformat(str(entry["timestamp"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("historical audit record timestamp is invalid") from exc
            if event_time.tzinfo is None:
                raise ValueError("historical audit record timestamp must include a timezone")
            event_time = event_time.astimezone(timezone.utc)
            if not (period_start <= event_time < period_end):
                raise ValueError("historical audit record falls outside the requested reporting period")
        if int(report_period.get("source_record_count", -1)) != len(audit):
            raise ValueError("historical audit source count does not match report records")
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
    coverage_text = (
        f"<b>Activity reporting period:</b> {period_start.strftime('%Y-%m-%d %H:%M:%S UTC')} "
        f"to {period_end.strftime('%Y-%m-%d %H:%M:%S UTC')} (start inclusive, end exclusive)<br/>"
        f"<b>Historical activity records:</b> {len(audit)} verified, tenant-matched records<br/>"
        f"<b>Audit checkpoint:</b> {html.escape(_plain(report_period.get('snapshot_head'), 80))}<br/>"
        "<b>Other monitoring figures:</b> Current snapshot at report generation time"
    ) if report_period is not None else (
        "<b>Coverage:</b> Current monitoring snapshot and the available recent activity summary"
    )
    story = [
        Paragraph("CyberGuardian", styles["CGTitle"]),
        Paragraph("Client Security & Monitoring Report", styles["Heading2"]),
        Paragraph("Prepared by TrinTech Digital Defense", styles["CGSub"]),
        Spacer(1, 8),
        Paragraph(
            f"<b>Client reference:</b> {html.escape(_plain(tenant_id, 100))}<br/>"
            f"<b>Generated:</b> {generated_at.astimezone(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}<br/>"
            f"{coverage_text}",
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
        if report_period is not None:
            story.append(Paragraph("Historical activity source records", styles["CGSection"]))
            story.append(Paragraph(
                "Each row identifies a verified audit-ledger record included in this reporting period. "
                "Times are UTC. The start is inclusive and the end is exclusive.",
                styles["CGSmall"],
            ))
            source_rows = [["Time (UTC)", "Recorded activity", "Source record ID"]]
            for entry in audit:
                event_time = datetime.fromisoformat(str(entry["timestamp"]).replace("Z", "+00:00"))
                event_label = translate(entry.get("event") or entry.get("action") or "Recorded activity")
                source_rows.append([
                    event_time.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    html.escape(_plain(event_label, 100)),
                    html.escape(_plain(entry["source_record_id"], 80)),
                ])
            source_table = Table(
                source_rows,
                colWidths=[1.35*inch, 2.0*inch, 2.8*inch],
                repeatRows=1,
            )
            source_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eef4f8")),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 6.5),
                ("GRID", (0,0), (-1,-1), .3, colors.HexColor("#d5e0e8")),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("TOPPADDING", (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ]))
            story.append(source_table)
    else:
        empty_activity = (
            "No activity records were found in the selected historical reporting period."
            if report_period is not None else
            "No recent activity records were returned."
        )
        story.append(Paragraph(empty_activity, styles["CGBody"]))
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
            (
                "Historical activity is read from the verified append-only audit ledger for the exact UTC "
                "reporting interval shown above. Each included activity row carries its source record ID. "
                "Other figures are current monitoring snapshots, not historical time-series totals. "
                "Missing or unscoped audit records are excluded rather than assigned to a client. "
                "This is an operational summary, not a certification, forensic conclusion or guarantee of security."
            ) if report_period is not None else (
                "This report was assembled from the authenticated dashboard's client-scoped monitoring summary, "
                "device list, approval queue, remembered-issue view, activity records and recent digest. "
                "Counts reflect the data returned by those services at report time. Missing data is not treated "
                "as zero. This is an operational summary, not a certification, forensic conclusion or guarantee of security."
            ),
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
