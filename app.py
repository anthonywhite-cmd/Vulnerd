#!/usr/bin/env python3
"""
Vulnerd Web — Local Security Report Card Interface
---------------------------------------------------
Run with: python3 app.py
Then open http://localhost:5000 in your browser

Dependencies (same as vulnerd.py):
  pip install google-generativeai reportlab python-dotenv
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import io
import json
from email import policy as email_policy
from email.parser import BytesParser
import os
import csv
import sys
import hashlib
import smtplib
import secrets
import tempfile
import threading
import webbrowser
from datetime import datetime
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

# Load .env file — supports both '.env' and 'env' naming
_env_path = Path(__file__).parent / '.env'
if not _env_path.exists():
    _env_path = Path(__file__).parent / 'env'
load_dotenv(dotenv_path=_env_path)

try:
    from google import genai as google_genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from reportlab.lib.pagesizes import letter as page_letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# ── CONFIG ──────────────────────────────────────────────────────────────────

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
EMAIL_SENDER   = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
SMTP_SERVER    = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("SMTP_PORT", 465))

BASE_DIR   = Path(__file__).parent
REPORT_DIR = BASE_DIR / 'reports'
REPORT_DIR.mkdir(exist_ok=True)

# In-memory store: token -> (pdf_path, score, letter)
pdf_store = {}

# ── GRADING ENGINE ───────────────────────────────────────────────────────────

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

GRADE_COLORS = {
    "A":  "#1a7a1a", "A-": "#2d8a2d",
    "B+": "#4a7c1a", "B":  "#6b8e23", "B-": "#8b9a1a",
    "C+": "#b8860b", "C":  "#cc8800", "C-": "#cc6600",
    "D+": "#cc4400", "D":  "#cc2200", "D-": "#aa0000",
    "F":  "#880000",
}

def calculate_score(counts, total):
    if total == 0:
        return 100
    deductions = (
        counts.get("Critical", 0) * 20 +
        counts.get("High",     0) * 8  +
        counts.get("Medium",   0) * 3  +
        counts.get("Low",      0) * 1
    )
    return max(0, 100 - deductions)

def score_to_letter(score):
    if score >= 93: return "A"
    if score >= 90: return "A-"
    if score >= 87: return "B+"
    if score >= 83: return "B"
    if score >= 80: return "B-"
    if score >= 77: return "C+"
    if score >= 73: return "C"
    if score >= 70: return "C-"
    if score >= 67: return "D+"
    if score >= 63: return "D"
    if score >= 60: return "D-"
    return "F"

def grade_commentary(letter):
    comments = {
        "A":  "Excellent work — this is a well-maintained environment and it shows. Keep up the discipline and schedule your next scan to stay ahead.",
        "A-": "Really strong results overall. A focused sprint will close the remaining loose ends cleanly.",
        "B+": "Good job — your core security posture is healthy. A handful of high-severity items need attention, but nothing here is unmanageable.",
        "B":  "Solid foundation with some meaningful gaps to close. Everything in this report is fixable with focused effort.",
        "B-": "You're in passing territory, and the path to improvement is clear. A structured remediation sprint would move this score up quickly.",
        "C+": "There is real work to do here, but you have a clear picture of what needs attention.",
        "C":  "This score reflects meaningful exposure that warrants prompt attention. Several findings are commonly targeted — address Critical and High items first.",
        "C-": "The Critical and High findings need to move to the top of the queue. Start there for the biggest impact on your risk posture.",
        "D+": "Several high-priority items need immediate attention. The remediation plan addresses the most urgent fixes.",
        "D":  "This report contains findings that need urgent remediation. The Critical vulnerabilities should be treated as a priority this week.",
        "D-": "Immediate action is recommended on the Critical findings. Please share this with your security lead or IT team right away.",
        "F":  "This report requires immediate escalation. The findings represent serious exposure and should be reviewed with your security team today.",
    }
    return comments.get(letter, "")

# ── CSV PARSER ───────────────────────────────────────────────────────────────

def parse_nessus_csv(file_path):
    """Parse a Nessus CSV export. Returns sorted list of findings."""
    vulns = []
    try:
        with open(file_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                severity = row.get("Risk", "None").strip()
                if severity == "None":
                    continue
                vulns.append({
                    "name":        row.get("Name",        "Unknown").strip(),
                    "severity":    severity,
                    "host":        row.get("Host",        "N/A").strip(),
                    "port":        row.get("Port",        "N/A").strip(),
                    "protocol":    row.get("Protocol",    "N/A").strip(),
                    "cve":         row.get("CVE",         "N/A").strip(),
                    "description": row.get("Description", "").strip()[:300],
                    "solution":    row.get("Solution",    "").strip()[:200],
                })
    except Exception as e:
        return []
    vulns.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return vulns

def summarize_vulns(vulns, score, letter):
    counts = Counter(v["severity"] for v in vulns)
    top    = vulns[:25]
    lines  = [
        f"SECURITY SCORE: {score}/100  |  GRADE: {letter}",
        f"TOTAL FINDINGS: {len(vulns)}",
        f"BREAKDOWN: Critical={counts.get('Critical',0)}, High={counts.get('High',0)}, "
        f"Medium={counts.get('Medium',0)}, Low={counts.get('Low',0)}",
        "",
        "TOP FINDINGS (sorted by severity):",
    ]
    for v in top:
        lines.append(f"  [{v['severity']}] {v['name']} | Host: {v['host']} | CVE: {v['cve']}")
        if v["solution"]:
            lines.append(f"    -> Fix: {v['solution']}")
    return "\n".join(lines)

def summarize_trend(reports_data):
    lines = [f"TREND ANALYSIS — LAST {len(reports_data)} REPORTS", ""]
    for r in reports_data:
        counts = Counter(v["severity"] for v in r["vulns"])
        score  = calculate_score(counts, len(r["vulns"]))
        letter = score_to_letter(score)
        lines.append(
            f"Report: {r['filename']}  |  Date: {r['date']}  |  Grade: {letter} ({score}/100)"
        )
        lines.append(
            f"  Critical={counts.get('Critical',0)}, High={counts.get('High',0)}, "
            f"Medium={counts.get('Medium',0)}, Low={counts.get('Low',0)}, Total={len(r['vulns'])}"
        )
        lines.append("")
    return "\n".join(lines)

# ── AI PROMPTS ───────────────────────────────────────────────────────────────

SINGLE_REPORT_PROMPT = """
You are Vulnerd, a helpful and friendly security analysis assistant. Your job is to turn
vulnerability scan data into a clear, professional security report card that is easy to
understand and act on.

Your tone is warm, encouraging, and supportive — like a knowledgeable colleague who wants
to help the team succeed. You are honest about risks, but never alarmist or condescending.
When findings are serious, you explain why calmly and focus on the solution.

Format EXACTLY as follows. Plain text only — no markdown, no asterisks, no bullet dashes:

EXECUTIVE SUMMARY
[2-3 sentences. A clear, calm overview of the current security posture. Mention the grade,
the total finding count, and the most important area to focus on.]

KEY FINDINGS
[The most significant vulnerabilities, starting with highest severity. For each: what it is,
what risk it introduces, and what resolving it would do. Keep the language informative, not alarming.]

CONTRIBUTING FACTORS
[What patterns in the data suggest about the environment — patching cadence, configuration
practices. Frame constructively as observations, not criticism.]

RECOMMENDATIONS
[A numbered, prioritized action list. Clear and specific — what to address first, what can
follow, and why the order matters. Each item should feel achievable.]

THREAT CONTEXT
[For the top 3-5 findings, explain what these vulnerabilities mean in the real world.
Who exploits them? What does a real attack look like? What is the business consequence?
Be specific and grounded to help a non-technical reader understand the stakes.]

WHO TO CALL
[Based on the findings, what kind of help does this organization need? Be specific:
contact their managed IT provider, an incident response firm, a patch management vendor?
What should they ask for? Make this actionable for today.]

INSTRUCTOR'S NOTE
[A short, friendly closing paragraph. Acknowledge what the team is doing well, highlight
the one area that will make the biggest difference, and end on an encouraging note.]
"""

TREND_PROMPT = """
You are Vulnerd, a helpful and friendly security analysis assistant reviewing multiple
vulnerability scans over time to help a team understand their security progress.

Your tone is warm, encouraging, and data-driven. You celebrate genuine improvement and
frame all feedback constructively — like a semester progress report written by someone
who wants the student to succeed.

Format EXACTLY as follows. Plain text only — no markdown, no asterisks, no bullet dashes:

PROGRESS SUMMARY
[A clear overview of the trend across all scans. Is the environment improving, holding
steady, or showing new areas of concern? Mention the grade trajectory.]

SCAN-BY-SCAN REVIEW
[Walk through each report chronologically. For each: note the grade, what changed from
the prior scan, and what that change suggests. Acknowledge improvements explicitly.]

PATTERNS TO ADDRESS
[Findings that appear across multiple scans. Explain why recurring items are worth
prioritizing and suggest what process change would resolve them over time.]

AREAS OF IMPROVEMENT
[What has genuinely gotten better across the scans? Specific reductions in severity
categories, resolved findings, or positive trends. Be specific and acknowledge the work.]

RECOMMENDED NEXT STEPS
[Program-level recommendations — process improvements, policy suggestions, or team
practices that would help sustain or accelerate improvement.]

THREAT CONTEXT
[Based on the recurring and highest-severity findings, what does the threat landscape
look like? What kinds of attackers target these vulnerability types? What is the realistic
business consequence if these exposures are exploited over time?]

WHO TO CALL
[Given the trend data, what kind of ongoing support does this organization need?
Make this concrete enough that a non-technical manager can act on it immediately.]

PROGRESS REPORT COMMENT
[A warm, encouraging closing paragraph. Summarize the trajectory, acknowledge the effort,
and give the team a clear, motivating picture of what success looks like in the next scan.]
"""

def analyze_with_gemini(summary_text, trend_mode=False):
    if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
        return (
            "EXECUTIVE SUMMARY\n"
            "AI analysis is not available — no Gemini API key found or library not installed. "
            "Please check your .env file and ensure google-generativeai is installed.\n\n"
            "KEY FINDINGS\nPlease review your scan data manually using the grade and breakdown above.\n\n"
            "INSTRUCTOR'S NOTE\nAdd your GEMINI_API_KEY to the env file to unlock full AI analysis!"
        )
    try:
        client = google_genai.Client(api_key=GEMINI_API_KEY)
        system = TREND_PROMPT if trend_mode else SINGLE_REPORT_PROMPT
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=summary_text,
            config=google_genai.types.GenerateContentConfig(
                system_instruction=system,
                max_output_tokens=8000,
            )
        )
        text = response.text
        for char in ["**", "## ", "# ", "- "]:
            text = text.replace(char, "")
        return text.strip()
    except Exception as e:
        return f"EXECUTIVE SUMMARY\nAI analysis error: {e}\n\nINSTRUCTOR'S NOTE\nCheck your API key and try again."

# ── COMPLIANCE ENGINE ────────────────────────────────────────────────────────

BUSINESS_FRAMEWORK_MAP = {
    "healthcare":  "HIPAA",
    "retail":      "PCI-DSS",
    "government":  "NIST 800-53",
    "education":   "FERPA",
    "general":     "CIS Controls",
}

COMPLIANCE_PROMPT = """
You are a compliance analysis engine for Vulnerd. Given vulnerability scan data and a business type,
analyze the compliance posture and return structured JSON.

Map business types to frameworks:
  healthcare → HIPAA
  retail     → PCI-DSS
  government → NIST 800-53
  education  → FERPA
  general    → CIS Controls

Return ONLY valid JSON — no markdown, no code blocks, no extra text. Use this exact structure:
{
  "framework_name": "short name e.g. HIPAA",
  "framework_full": "full official name",
  "attributes": [
    {
      "name": "plain English attribute name, no jargon",
      "score": 0-100,
      "blurb": "one plain English sentence describing this attribute's status"
    }
  ],
  "what_is_it": "2-3 sentences explaining what this framework is in plain English. No policy codes. No acronym soup. Write as if explaining to a business owner who has never heard of it.",
  "why_it_matters": "2-3 sentences on why this specific type of business must care about this. Focus on consequences, not rules.",
  "real_story": "A real or highly realistic example of a similar business that faced serious consequences because of gaps exactly like these. Be specific — name the type of business, what happened, and what it cost them. Keep it under 4 sentences.",
  "fix_cost_low": integer dollars,
  "fix_cost_high": integer dollars,
  "breach_cost_low": integer dollars,
  "breach_cost_high": integer dollars,
  "cost_context": "2 sentences putting these numbers in plain English context. Compare the two costs directly so the ROI of fixing things is obvious."
}

For attribute scores: base them on the actual scan findings. More critical/high findings related to that
attribute = lower score. Use 5 attributes that are most relevant to the chosen framework.
Score 0-40 = critical gap, 41-70 = needs work, 71-100 = reasonable posture.
"""

def extract_json(text):
    """Robustly extract the first complete JSON object from a string."""
    import re
    # Strip markdown code fences
    text = re.sub(r"```(?:json)?", "", text).strip()
    # Find the outermost { ... }
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in response")
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i+1])
    raise ValueError("Unbalanced JSON braces in response")

def analyze_compliance(scan_summary, business_type):
    """Run compliance analysis and return structured data for the dashboard."""
    if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
        print("[compliance] Skipping — Gemini not available")
        return None
    framework = BUSINESS_FRAMEWORK_MAP.get(business_type, "CIS Controls")
    payload   = f"BUSINESS TYPE: {business_type}\nFRAMEWORK: {framework}\n\nSCAN DATA:\n{scan_summary}"
    try:
        client   = google_genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=payload,
            config=google_genai.types.GenerateContentConfig(
                system_instruction=COMPLIANCE_PROMPT,
                max_output_tokens=4000,
            )
        )
        text = response.text.strip()
        print(f"[compliance] Raw response ({len(text)} chars): {text[:200]}...")
        result = extract_json(text)
        print(f"[compliance] Parsed OK — framework: {result.get('framework_name')}, attrs: {len(result.get('attributes', []))}")
        return result
    except Exception as e:
        print(f"[compliance] ERROR: {e}")
        return None

# ── PDF GENERATOR ─────────────────────────────────────────────────────────────

ALL_SECTION_HEADERS = {
    "EXECUTIVE SUMMARY", "KEY FINDINGS", "CONTRIBUTING FACTORS",
    "RECOMMENDATIONS", "THREAT CONTEXT", "WHO TO CALL", "INSTRUCTOR'S NOTE",
    "PROGRESS SUMMARY", "SCAN-BY-SCAN REVIEW", "PATTERNS TO ADDRESS",
    "AREAS OF IMPROVEMENT", "RECOMMENDED NEXT STEPS", "PROGRESS REPORT COMMENT",
}

def generate_pdf(analysis_text, report_meta, output_path):
    doc    = SimpleDocTemplate(
        output_path, pagesize=page_letter,
        leftMargin=0.85*inch, rightMargin=0.85*inch,
        topMargin=0.85*inch,  bottomMargin=0.85*inch,
    )
    styles = getSampleStyleSheet()
    story  = []

    title_style     = ParagraphStyle("vtitle", parent=styles["Heading1"],
        fontSize=20, spaceAfter=2, textColor=colors.HexColor("#0a0a0a"), fontName="Helvetica-Bold")
    subtitle_style  = ParagraphStyle("vsub", parent=styles["Normal"],
        fontSize=10, spaceAfter=2, textColor=colors.HexColor("#444444"), fontName="Helvetica")
    meta_style      = ParagraphStyle("vmeta", parent=styles["Normal"],
        fontSize=8, spaceAfter=3, textColor=colors.HexColor("#666666"), fontName="Courier")
    section_style   = ParagraphStyle("vsection", parent=styles["Heading2"],
        fontSize=11, spaceBefore=14, spaceAfter=4,
        textColor=colors.HexColor("#1a1a2e"), fontName="Helvetica-Bold")
    body_style      = ParagraphStyle("vbody", parent=styles["Normal"],
        fontSize=10, leading=15, spaceAfter=5,
        textColor=colors.HexColor("#1a1a1a"), fontName="Helvetica")
    commentary_style = ParagraphStyle("vcommentary", parent=styles["Normal"],
        fontSize=10, leading=14, spaceAfter=6,
        textColor=colors.HexColor("#2a2a4a"), fontName="Helvetica-Oblique",
        leftIndent=8, rightIndent=8)

    story.append(Paragraph("VULNERD SECURITY REPORT CARD", title_style))
    story.append(Paragraph(
        f"Automated Vulnerability Analysis  |  {datetime.now().strftime('%B %d, %Y')}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0a0a0a"), spaceAfter=8))
    story.append(Paragraph(f"Source: {report_meta.get('filename', 'N/A')}", meta_style))
    story.append(Paragraph(f"SHA-256: {report_meta.get('hash', 'N/A')}", meta_style))
    story.append(Spacer(1, 0.15*inch))

    score  = report_meta.get("score")
    letter = report_meta.get("letter")

    if score is not None and letter is not None:
        grade_color = colors.HexColor(GRADE_COLORS.get(letter, "#333333"))
        counts      = report_meta.get("counts", {})
        total       = report_meta.get("total", 0)

        grade_cell_text = (
            f'<font size="42" color="white"><b>{letter}</b></font><br/>'
            f'<font size="14" color="white">{score}/100</font>'
        )
        breakdown_data = [
            ["Severity", "Count", "Deduction"],
            ["Critical", str(counts.get("Critical", 0)), f"-{counts.get('Critical',0)*20} pts"],
            ["High",     str(counts.get("High",     0)), f"-{counts.get('High',0)*8} pts"],
            ["Medium",   str(counts.get("Medium",   0)), f"-{counts.get('Medium',0)*3} pts"],
            ["Low",      str(counts.get("Low",      0)), f"-{counts.get('Low',0)*1} pt"],
            ["TOTAL",    str(total),                     f"Score: {score}/100"],
        ]
        bd_table = Table(breakdown_data, colWidths=[1.2*inch, 0.8*inch, 1.2*inch])
        bd_table.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0),  colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("ALIGN",          (0,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,1), (-1,-2), [colors.HexColor("#f5f5f5"), colors.white]),
            ("BACKGROUND",     (0,-1),(-1,-1), colors.HexColor("#e8e8e8")),
            ("FONTNAME",       (0,-1),(-1,-1), "Helvetica-Bold"),
            ("GRID",           (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING",     (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
        ]))
        grade_para  = Paragraph(grade_cell_text, ParagraphStyle("grade_cell", alignment=1, leading=20))
        outer_table = Table([[grade_para, bd_table]], colWidths=[1.4*inch, None])
        outer_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(0,0),  grade_color),
            ("VALIGN",        (0,0),(-1,-1),"MIDDLE"),
            ("ALIGN",         (0,0),(0,0),  "CENTER"),
            ("LEFTPADDING",   (0,0),(0,0),  10),
            ("RIGHTPADDING",  (0,0),(0,0),  10),
            ("TOPPADDING",    (0,0),(0,0),  14),
            ("BOTTOMPADDING", (0,0),(0,0),  14),
            ("LEFTPADDING",   (1,0),(1,0),  14),
            ("BOX",           (0,0),(-1,-1), 1, colors.HexColor("#cccccc")),
        ]))
        story.append(outer_table)
        story.append(Spacer(1, 0.12*inch))

        commentary = report_meta.get("commentary", "")
        if commentary:
            cb = Table([[Paragraph(f'"{commentary}"', commentary_style)]], colWidths=[doc.width])
            cb.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#f0f0f8")),
                ("BOX",           (0,0),(-1,-1), 0.5, colors.HexColor("#aaaacc")),
                ("LEFTPADDING",   (0,0),(-1,-1), 10),
                ("RIGHTPADDING",  (0,0),(-1,-1), 10),
                ("TOPPADDING",    (0,0),(-1,-1), 8),
                ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ]))
            story.append(cb)
            story.append(Spacer(1, 0.15*inch))

    trend_grades = report_meta.get("trend_grades")
    if trend_grades:
        story.append(Paragraph("GRADE HISTORY", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=4))
        tg_data = [["Report", "Date", "Findings", "Score", "Grade"]]
        for tg in trend_grades:
            tg_data.append([tg["filename"][:35], tg["date"], str(tg["total"]),
                            f"{tg['score']}/100", tg["letter"]])
        tg_table = Table(tg_data, colWidths=[2.3*inch, 1.0*inch, 0.8*inch, 0.8*inch, 0.6*inch])
        tg_table.setStyle(TableStyle([
            ("BACKGROUND",     (0,0),(-1,0),  colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",      (0,0),(-1,0),  colors.white),
            ("FONTNAME",       (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0),(-1,-1), 9),
            ("ALIGN",          (1,0),(-1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.HexColor("#f5f5f5"), colors.white]),
            ("GRID",           (0,0),(-1,-1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING",     (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",  (0,0),(-1,-1), 4),
        ]))
        story.append(tg_table)
        story.append(Spacer(1, 0.15*inch))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=6))

    for line in analysis_text.splitlines():
        stripped = line.strip()
        if not stripped:
            story.append(Spacer(1, 0.04*inch))
        elif stripped in ALL_SECTION_HEADERS:
            story.append(Paragraph(stripped, section_style))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"), spaceAfter=2))
        else:
            safe = stripped.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            story.append(Paragraph(safe, body_style))

    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        f"Generated by Vulnerd  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"Data source: {report_meta.get('filename', 'N/A')}",
        ParagraphStyle("footer", parent=styles["Normal"],
            fontSize=7, textColor=colors.HexColor("#999999"), fontName="Helvetica", spaceBefore=4)
    ))
    doc.build(story)

# ── EMAIL ─────────────────────────────────────────────────────────────────────

def send_report_email(recipient, pdf_path, score=None, letter=None):
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        raise ValueError("Email credentials not configured in env file.")
    grade_line  = f" — Grade: {letter} ({score}/100)" if score and letter else ""
    msg         = EmailMessage()
    msg["Subject"] = f"Vulnerd Security Report Card{grade_line}  |  {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"]    = EMAIL_SENDER
    msg["To"]      = recipient
    body_grade     = f"Final Grade: {letter} ({score}/100)\n\n" if score and letter else ""
    msg.set_content(
        f"Your Vulnerd Security Report Card is attached.\n\n"
        f"{body_grade}"
        "Detailed analysis, remediation priorities, and next steps are inside.\n\n"
        "— Vulnerd\n  Your Nerdy Security Classmate"
    )
    with open(pdf_path, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                           filename=os.path.basename(pdf_path))
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
        smtp.send_message(msg)

# ── ANALYSIS PIPELINE (web version) ──────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_sections(analysis_text, is_trend=False):
    """Split AI analysis text into titled sections for the web UI."""
    single_headers = [
        ("EXECUTIVE SUMMARY",   "📋"),
        ("KEY FINDINGS",        "🔍"),
        ("CONTRIBUTING FACTORS","🧩"),
        ("RECOMMENDATIONS",     "✅"),
        ("THREAT CONTEXT",      "⚠️"),
        ("WHO TO CALL",         "📞"),
        ("INSTRUCTOR'S NOTE",   "🎓"),
    ]
    trend_headers = [
        ("PROGRESS SUMMARY",      "📈"),
        ("SCAN-BY-SCAN REVIEW",   "📅"),
        ("PATTERNS TO ADDRESS",   "🔄"),
        ("AREAS OF IMPROVEMENT",  "⬆️"),
        ("RECOMMENDED NEXT STEPS","🚀"),
        ("THREAT CONTEXT",        "⚠️"),
        ("WHO TO CALL",           "📞"),
        ("PROGRESS REPORT COMMENT","💬"),
    ]
    headers_list = trend_headers if is_trend else single_headers
    all_titles   = {h[0] for h in headers_list}
    icon_map     = {h[0]: h[1] for h in headers_list}

    sections      = []
    current_title = None
    current_lines = []

    for line in analysis_text.splitlines():
        stripped = line.strip()
        if stripped in all_titles:
            if current_title:
                sections.append({
                    "title":   current_title,
                    "content": "\n".join(current_lines).strip(),
                    "icon":    icon_map.get(current_title, "📄"),
                })
            current_title = stripped
            current_lines = []
        elif current_title:
            current_lines.append(stripped)

    if current_title:
        sections.append({
            "title":   current_title,
            "content": "\n".join(current_lines).strip(),
            "icon":    icon_map.get(current_title, "📄"),
        })
    return sections

def run_single_report_web(filename, file_path, business_type=None):
    file_hash  = sha256_file(file_path)
    vulns      = parse_nessus_csv(file_path)
    if not vulns:
        raise ValueError("No actionable vulnerabilities found in this file. Make sure it's a valid Nessus CSV export.")

    counts     = Counter(v["severity"] for v in vulns)
    score      = calculate_score(counts, len(vulns))
    letter     = score_to_letter(score)
    commentary = grade_commentary(letter)
    summary    = summarize_vulns(vulns, score, letter)
    analysis   = analyze_with_gemini(summary, trend_mode=False)
    sections   = parse_sections(analysis, is_trend=False)

    # Run compliance analysis if business type was selected
    compliance = None
    if business_type and business_type != "none":
        compliance = analyze_compliance(summary, business_type)

    out_name = f"Vulnerd_ReportCard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = str(REPORT_DIR / out_name)
    generate_pdf(analysis, {
        "filename":    filename,
        "hash":        file_hash,
        "total":       len(vulns),
        "counts":      counts,
        "score":       score,
        "letter":      letter,
        "commentary":  commentary,
        "trend_grades": None,
    }, out_path)

    token = secrets.token_hex(16)
    pdf_store[token] = (out_path, score, letter)

    return {
        "success":     True,
        "mode":        "single",
        "filename":    filename,
        "score":       score,
        "letter":      letter,
        "grade_color": GRADE_COLORS.get(letter, "#333333"),
        "commentary":  commentary,
        "counts":      dict(counts),
        "total":       len(vulns),
        "sections":    sections,
        "pdf_token":   token,
        "compliance":  compliance,
        "business_type": business_type,
    }

def run_trend_analysis_web(files):
    """files: list of (filename, file_path) tuples"""
    files = files[:5]
    reports_data = []
    trend_grades = []

    for filename, file_path in files:
        vulns  = parse_nessus_csv(file_path)
        counts = Counter(v["severity"] for v in vulns)
        score  = calculate_score(counts, len(vulns))
        letter = score_to_letter(score)
        mtime  = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d")
        reports_data.append({"filename": filename, "date": mtime, "vulns": vulns})
        trend_grades.append({
            "filename": filename, "date": mtime,
            "total": len(vulns), "score": score, "letter": letter,
        })

    summary  = summarize_trend(reports_data)
    analysis = analyze_with_gemini(summary, trend_mode=True)
    sections = parse_sections(analysis, is_trend=True)

    out_name = f"Vulnerd_TrendReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = str(REPORT_DIR / out_name)
    generate_pdf(analysis, {
        "filename":    f"Trend — {len(files)} reports",
        "hash":        "N/A (multi-file analysis)",
        "score":       None,
        "letter":      None,
        "commentary":  None,
        "trend_grades": trend_grades,
    }, out_path)

    token = secrets.token_hex(16)
    pdf_store[token] = (out_path, None, None)

    return {
        "success":     True,
        "mode":        "trend",
        "filename":    f"{len(files)} scan files",
        "score":       None,
        "letter":      None,
        "grade_color": None,
        "commentary":  None,
        "counts":      None,
        "total":       None,
        "trend_grades": trend_grades,
        "sections":    sections,
        "pdf_token":   token,
    }

# ── MULTIPART PARSER (replaces deprecated cgi module) ────────────────────────

def parse_multipart(content_type, body):
    """Parse multipart/form-data using the email module (works on Python 3.13+)."""
    raw = b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + body
    msg = BytesParser(policy=email_policy.default).parsebytes(raw)

    fields = {}
    files  = []

    if msg.is_multipart():
        for part in msg.iter_parts():
            disp = part.get('Content-Disposition', '')
            if not disp:
                continue
            name     = None
            filename = None
            for token in disp.split(';'):
                token = token.strip()
                if token.startswith('name='):
                    name = token[5:].strip('"')
                elif token.startswith('filename='):
                    filename = token[9:].strip('"')
            if not name:
                continue
            payload = part.get_payload(decode=True) or b''
            if filename:
                files.append((name, filename, payload))
            else:
                fields[name] = payload.decode('utf-8', errors='replace')

    return fields, files

# ── HTTP SERVER ───────────────────────────────────────────────────────────────

class VulnerdHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # silence request logs

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html_path = BASE_DIR / "templates" / "index.html"
            try:
                with open(html_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", len(content))
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"templates/index.html not found")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/analyze":
            self._handle_analyze()
        elif self.path == "/send-report":
            self._handle_send_report()
        elif self.path == "/ask":
            self._handle_ask()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_analyze(self):
        temp_paths = []
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body           = self.rfile.read(content_length)
            content_type   = self.headers.get("Content-Type", "")

            fields, files  = parse_multipart(content_type, body)
            mode           = fields.get("mode", "single")
            business_type  = fields.get("business_type", "none")

            # Save uploaded CSV files to temp location
            for (_name, filename, data) in files:
                if filename.lower().endswith(".csv"):
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
                    tmp.write(data)
                    tmp.close()
                    temp_paths.append((filename, tmp.name))

            if not temp_paths:
                self.send_json({"error": "No valid CSV files found. Please upload Nessus CSV exports."}, 400)
                return

            if mode == "trend" and len(temp_paths) >= 2:
                result = run_trend_analysis_web(temp_paths)
            else:
                result = run_single_report_web(*temp_paths[0], business_type=business_type)

            self.send_json(result)

        except Exception as e:
            self.send_json({"error": str(e)}, 500)
        finally:
            for _, p in temp_paths:
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def _handle_send_report(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body           = json.loads(self.rfile.read(content_length))
            email          = body.get("email", "").strip()
            token          = body.get("pdf_token", "")

            if not email:
                self.send_json({"error": "Email address is required."}, 400)
                return
            if token not in pdf_store:
                self.send_json({"error": "Report not found. Please run analysis again."}, 404)
                return

            pdf_path, score, letter = pdf_store[token]
            send_report_email(email, pdf_path, score, letter)
            self.send_json({"success": True})

        except Exception as e:
            self.send_json({"error": str(e)}, 500)

    def _handle_ask(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body           = json.loads(self.rfile.read(content_length))
            question       = body.get("question", "").strip()
            scan_context   = body.get("scan_context", "")

            if not question:
                self.send_json({"error": "No question provided."}, 400)
                return

            answer = ask_vulnerd(question, scan_context)
            self.send_json({"answer": answer})

        except Exception as e:
            self.send_json({"error": str(e)}, 500)

# ── CHAT ENGINE ───────────────────────────────────────────────────────────────

CHAT_PROMPT = """
You are Vulnerd, a cybersecurity assistant with the personality of a brilliant nerdy classmate
who genuinely wants you to succeed and understand this stuff. You explain things like you're
tutoring a friend over coffee — warm, clear, a little excited about security topics, and never
condescending. You use real-world analogies and plain English to make complex concepts click.

Rules for your answers:
- Keep it conversational, not textbook. Short paragraphs, not walls of text.
- Use analogies when they help ("think of it like leaving your front door unlocked...")
- Be specific and practical — give the person something they can actually do or understand
- If it's a scary topic, be honest about the risk but calm and solution-focused
- Show genuine enthusiasm when something is interesting ("okay so this one is actually wild...")
- Never use bullet points or markdown formatting — just friendly flowing paragraphs
- If the question relates to their scan results, reference that context directly
- Keep answers focused — 3-5 paragraphs max unless the topic really needs more depth
"""

def ask_vulnerd(question, scan_context=""):
    """Answer a user question using Gemini with Vulnerd's personality."""
    if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
        return (
            "Oof, looks like I can't reach my brain right now — the Gemini API key isn't "
            "configured. Add your GEMINI_API_KEY to the env file and restart the app. "
            "Once that's set up I can answer all your questions! 🤓"
        )
    try:
        client  = google_genai.Client(api_key=GEMINI_API_KEY)
        payload = question
        if scan_context:
            payload = f"CONTEXT FROM THEIR SCAN:\n{scan_context}\n\nUSER QUESTION:\n{question}"

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=payload,
            config=google_genai.types.GenerateContentConfig(
                system_instruction=CHAT_PROMPT,
                max_output_tokens=800,
            )
        )
        text = response.text
        for char in ["**", "## ", "# ", "- "]:
            text = text.replace(char, "")
        return text.strip()
    except Exception as e:
        return f"Hmm, I hit a snag trying to answer that: {e}. Try again in a second!"

# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    port   = 5001
    server = HTTPServer(("", port), VulnerdHandler)
    url    = f"http://localhost:{port}"

    print("\n" + "=" * 54)
    print("  🤓  VULNERD — Security Report Card Engine")
    print("=" * 54)
    print(f"  Server running at: {url}")
    print("  Press Ctrl+C to stop.\n")

    threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋  Shutting down Vulnerd. Good luck out there!")

if __name__ == "__main__":
    main()
