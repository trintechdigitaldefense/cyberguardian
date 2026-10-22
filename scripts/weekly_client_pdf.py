#!/usr/bin/env python3
"""Generate client-facing weekly PDF from /v1/reports/weekly."""
from __future__ import annotations
import argparse, json, os, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def fetch_weekly(api: str, key: str) -> str:
    req = urllib.request.Request(api.rstrip("/") + "/v1/reports/weekly", headers={"X-API-Key": key, "Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode()

def fetch_json(api: str, key: str, path: str) -> dict:
    req = urllib.request.Request(api.rstrip("/") + path, headers={"X-API-Key": key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())

def build_pdf(text: str, scorecard: dict, out: Path, client_name: str = "Client") -> Path:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        from reportlab.lib.colors import HexColor
    except ImportError:
        out = out.with_suffix(".txt")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(f"CyberGuardian Weekly Digest — {client_name}\n\n{text}\n")
        print("reportlab not installed — wrote text:", out)
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out), pagesize=letter, leftMargin=0.75*inch, rightMargin=0.75*inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CGTitle", parent=styles["Heading1"], textColor=HexColor("#0e7490"), fontSize=18, spaceAfter=12)
    body = [Paragraph(f"CyberGuardian Weekly Digest — {client_name}", title_style),
            Paragraph(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · TrinTech Digital Defense", styles["Normal"]),
            Spacer(1, 12)]
    if scorecard:
        body.append(Paragraph(f"<b>Pilot scorecard:</b> {scorecard.get('status','—')} ({scorecard.get('score','—')})", styles["Normal"]))
        for c in scorecard.get("checks") or []:
            mark = "✓" if c.get("ok") else "✗"
            body.append(Paragraph(f"{mark} {c.get('label')}: {c.get('detail') or ''}", styles["Normal"]))
        body.append(Spacer(1, 12))
    body.append(Paragraph("<b>7-day summary</b>", styles["Heading2"]))
    body.append(Preformatted(text.replace("\t", " ")[:8000], styles["Code"], maxLineLength=95))
    body.append(Spacer(1, 16))
    body.append(Paragraph("<i>Supervised pilot — keep Client Mode ON for production hosts.</i>", styles["Normal"]))
    doc.build(body)
    print("Wrote", out)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("CYBERGUARDIAN_API", "http://127.0.0.1:8080"))
    ap.add_argument("--key", default=os.environ.get("CYBERGUARDIAN_API_KEY", ""))
    ap.add_argument("--out", default=str(ROOT / "data" / "reports" / "weekly.pdf"))
    ap.add_argument("--client", default="Client")
    args = ap.parse_args()
    if not args.key:
        creds = ROOT / "data" / "credentials.json"
        if creds.exists():
            args.key = json.loads(creds.read_text()).get("api_key") or ""
    if not args.key:
        print("Set CYBERGUARDIAN_API_KEY", file=sys.stderr); sys.exit(1)
    try:
        weekly = fetch_weekly(args.api, args.key)
    except Exception as e:
        weekly = f"(weekly endpoint unavailable: {e})\n"
    try:
        scorecard = fetch_json(args.api, args.key, "/v1/pilot/scorecard")
    except Exception:
        scorecard = {}
    build_pdf(weekly, scorecard, Path(args.out), client_name=args.client)

if __name__ == "__main__":
    main()
