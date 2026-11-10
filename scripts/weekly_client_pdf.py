#!/usr/bin/env python3
"""Generate a tenant-scoped client weekly PDF from verified gateway reports."""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import tempfile
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _request(api: str, key: str, path: str, tenant_id: str, accept: str):
    query = urllib.parse.urlencode({"tenant_id": tenant_id})
    url = api.rstrip("/") + path + "?" + query
    req = urllib.request.Request(
        url,
        headers={
            "X-API-Key": key,
            "X-Tenant-ID": tenant_id,
            "Accept": accept,
        },
    )
    return urllib.request.urlopen(req, timeout=15)


def fetch_weekly(api: str, key: str, tenant_id: str) -> str:
    with _request(api, key, "/v1/reports/weekly", tenant_id, "text/plain") as response:
        if response.status != 200:
            raise RuntimeError(f"weekly report endpoint returned HTTP {response.status}")
        result = response.read().decode("utf-8")
        if not result.strip():
            raise RuntimeError("weekly report endpoint returned an empty report")
        return result


def fetch_scorecard(api: str, key: str, tenant_id: str) -> dict:
    with _request(api, key, "/v1/pilot/scorecard", tenant_id, "application/json") as response:
        if response.status != 200:
            raise RuntimeError(f"pilot scorecard endpoint returned HTTP {response.status}")
        result = json.loads(response.read().decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("pilot scorecard response must be a JSON object")
        response_tenant = result.get("tenant_id")
        if response_tenant is not None and str(response_tenant) != tenant_id:
            raise RuntimeError("pilot scorecard tenant does not match requested tenant")
        return result


def build_pdf(
    text: str,
    scorecard: dict,
    out: Path,
    client_name: str = "Client",
    tenant_id: str = "",
) -> Path:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        from reportlab.lib.colors import HexColor
    except ImportError as exc:
        raise RuntimeError("ReportLab is required to generate a client PDF; install dashboard/report dependencies") from exc

    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out), pagesize=letter, leftMargin=0.75 * inch, rightMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CGTitle", parent=styles["Heading1"], textColor=HexColor("#0e7490"),
        fontSize=18, spaceAfter=12,
    )
    safe_client = html.escape(str(client_name))
    safe_tenant = html.escape(str(tenant_id))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = [
        Paragraph(f"CyberGuardian Weekly Digest — {safe_client}", title_style),
        Paragraph(f"Tenant: {safe_tenant}", styles["Normal"]),
        Paragraph(f"Generated {generated} · TrinTech Digital Defense", styles["Normal"]),
        Spacer(1, 12),
    ]
    if scorecard:
        status = html.escape(str(scorecard.get("status", "—")))
        score = html.escape(str(scorecard.get("score", "—")))
        body.append(Paragraph(f"<b>Pilot scorecard:</b> {status} ({score})", styles["Normal"]))
        for check in scorecard.get("checks") or []:
            if not isinstance(check, dict):
                continue
            mark = "✓" if check.get("ok") else "✗"
            label = html.escape(str(check.get("label") or "Unnamed check"))
            detail = html.escape(str(check.get("detail") or ""))
            body.append(Paragraph(f"{mark} {label}: {detail}", styles["Normal"]))
        body.append(Spacer(1, 12))
    body.append(Paragraph("7-day summary", styles["Heading2"]))
    body.append(Preformatted(str(text).replace("\t", " ")[:12000], styles["Code"], maxLineLength=95))
    body.append(Spacer(1, 16))
    body.append(Paragraph(
        "Supervised pilot — keep Client Mode ON for production hosts.",
        styles["Normal"],
    ))
    doc.build(body)
    return out


def _safe_csv_cell(value) -> str:
    text = str(value if value is not None else "")
    if text.lstrip().startswith(("=", "+", "-", "@", "\\t", "\\r")):
        return "'" + text
    return text


def build_csv(scorecard: dict, out: Path, *, tenant_id: str) -> Path:
    """Atomically export tenant-scoped scorecard rows with spreadsheet formula protection."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    checks = scorecard.get("checks") or []
    if not isinstance(checks, list):
        raise RuntimeError("scorecard checks must be a list")
    rows = checks or [{}]
    fd, temp_name = tempfile.mkstemp(prefix=out.name + ".", suffix=".tmp", dir=str(out.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=("tenant_id", "generated_at_utc", "status", "score", "check_label", "ok", "detail"),
            )
            writer.writeheader()
            generated = datetime.now(timezone.utc).isoformat()
            for check in rows:
                if not isinstance(check, dict):
                    raise RuntimeError("scorecard check entries must be objects")
                writer.writerow({
                    "tenant_id": _safe_csv_cell(tenant_id),
                    "generated_at_utc": generated,
                    "status": _safe_csv_cell(scorecard.get("status", "")),
                    "score": _safe_csv_cell(scorecard.get("score", "")),
                    "check_label": _safe_csv_cell(check.get("label", "")),
                    "ok": bool(check.get("ok", False)),
                    "detail": _safe_csv_cell(check.get("detail", "")),
                })
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, out)
        os.chmod(out, 0o600)
        dir_fd = os.open(str(out.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default=os.environ.get("CYBERGUARDIAN_API", "http://127.0.0.1:8080"))
    parser.add_argument("--key", default=os.environ.get("CYBERGUARDIAN_API_KEY", ""))
    parser.add_argument("--tenant-id", default=os.environ.get("CYBERGUARDIAN_TENANT", ""))
    parser.add_argument("--out", default=str(ROOT / "data" / "reports" / "weekly.pdf"))
    parser.add_argument("--csv-out", default="", help="optional tenant-scoped scorecard CSV output path")
    parser.add_argument("--client", default="Client")
    args = parser.parse_args()

    if not args.key:
        credentials = ROOT / "data" / "credentials.json"
        if credentials.exists():
            args.key = json.loads(credentials.read_text(encoding="utf-8")).get("api_key") or ""
    if not args.key:
        parser.error("Set CYBERGUARDIAN_API_KEY or provide --key")
    if not args.tenant_id:
        parser.error("A tenant is required: set CYBERGUARDIAN_TENANT or provide --tenant-id")

    # Fail closed: never publish a report that substitutes an error message for
    # missing source data or silently omits its scorecard.
    try:
        weekly = fetch_weekly(args.api, args.key, args.tenant_id)
        scorecard = fetch_scorecard(args.api, args.key, args.tenant_id)
    except Exception as exc:
        print(f"Report generation aborted: {exc}", file=sys.stderr)
        raise SystemExit(2)

    build_pdf(weekly, scorecard, Path(args.out), client_name=args.client, tenant_id=args.tenant_id)
    if args.csv_out:
        build_csv(scorecard, Path(args.csv_out), tenant_id=args.tenant_id)


if __name__ == "__main__":
    main()
