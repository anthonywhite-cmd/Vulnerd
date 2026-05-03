#!/usr/bin/env python3
"""
Vulnerd v5.0 - Automated Nessus Security Report Card Engine
------------------------------------------------------------
Your network's GPA, delivered straight to your inbox.

Usage:
  - Drop Nessus CSV exports into ./evidence_locker/
  - Run: python vulnerd.py
  - Pick: latest report OR trend analysis (last 5)
  - Enter stakeholder email
  - Done. Go touch grass.

Dependencies:
  pip install google-generativeai reportlab python-dotenv
"""

import os
import csv
import glob
import smtplib
import hashlib
from datetime import datetime
from email.message import EmailMessage
from collections import Counter

from dotenv import load_dotenv
from google import genai as google_genai
from reportlab.lib.pagesizes import letter as page_letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# ─── CONFIG ───────────────────────────────────────────────────────────────────
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
EMAIL_SENDER   = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
SMTP_SERVER    = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("SMTP_PORT", 465))

EVIDENCE_DIR = "./evidence_locker"
REPORT_DIR   = "./reports"

# ─── GRADING ENGINE ───────────────────────────────────────────────────────────

def calculate_score(counts, total):
    """
    Scoring rubric (100 points possible):
      - Each Critical:  -20 pts
      - Each High:       -8 pts
      - Each Medium:     -3 pts
      - Each Low:        -1 pt
    Floor is 0. No extra credit for zero vulns — that's just a baseline expectation.
    """
    if total == 0:
        return 100

    deductions = (
        counts.get("Critical", 0) * 20 +
        counts.get("High",     0) *  8 +
        counts.get("Medium",   0) *  3 +
        counts.get("Low",      0) *  1
    )
    return max(0, 100 - deductions)

def score_to_letter(score):
    """Classic letter grade. No grade inflation."""
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
    """
    Friendly tutor energy — encouraging, clear about urgency, never shaming.
    """
    comments = {
        "A":  "Excellent work — this is a well-maintained environment and it shows. "
              "Your patch management and configuration hygiene are in great shape. "
              "Keep up the discipline and schedule your next scan to stay ahead.",
        "A-": "Really strong results overall. There are a small number of loose ends worth "
              "addressing, but your fundamentals are clearly solid. A focused sprint will "
              "close these out cleanly.",
        "B+": "Good job — you're above average and your core security posture is healthy. "
              "A handful of high-severity items need attention, but nothing here is "
              "unmanageable. Prioritize those and you'll be in great shape.",
        "B":  "Solid foundation with some meaningful gaps to close. The good news is that "
              "everything in this report is fixable with focused effort. Review the "
              "remediation plan below and work through it systematically.",
        "B-": "You're in passing territory, and the path to improvement is clear. "
              "Some findings are close to remediated but need follow-through. "
              "A structured remediation sprint would move this score up quickly.",
        "C+": "There is real work to do here, but you have a clear picture of what needs "
              "attention. The findings span multiple severity levels — working through "
              "the prioritized list below will make a significant difference.",
        "C":  "This score reflects meaningful exposure that warrants prompt attention. "
              "Several findings in this report are commonly targeted — addressing the "
              "critical and high items first will have the biggest impact on your risk posture.",
        "C-": "The critical and high findings in this report need to move to the top of "
              "the queue. The remediation plan below is ordered by impact — starting "
              "there will help the team make fast, visible progress.",
        "D+": "There are several high-priority items here that need immediate attention. "
              "The remediation script in this report addresses the most urgent fix, and "
              "the action plan will help the team work through the rest systematically.",
        "D":  "This report contains findings that need urgent remediation. The critical "
              "vulnerabilities especially should be treated as a priority this week. "
              "Please review the remediation plan and escalate as needed.",
        "D-": "Immediate action is recommended on the critical findings in this report. "
              "Please share this with your security lead or IT team right away and use "
              "the remediation script as a starting point for rapid response.",
        "F":  "This report requires immediate escalation. The findings represent serious "
              "exposure and should be reviewed with your security team today. "
              "The remediation plan and script below are your starting point — please act on them promptly.",
    }
    return comments.get(letter, "No commentary available.")


# ─── CSV PARSER ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}

def parse_nessus_csv(file_path):
    """Parses a Nessus CSV export. Skips purely informational rows."""
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
        print(f"\n[!] Parse error on {os.path.basename(file_path)}: {e}")
        return []

    vulns.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return vulns


def summarize_vulns(vulns, score, letter):
    """Builds the Gemini prompt payload — structured, dense, no fluff."""
    counts = Counter(v["severity"] for v in vulns)
    top    = vulns[:25]

    lines = [
        f"SECURITY SCORE: {score}/100  |  GRADE: {letter}",
        f"TOTAL FINDINGS: {len(vulns)}",
        f"BREAKDOWN: Critical={counts.get('Critical',0)}, High={counts.get('High',0)}, "
        f"Medium={counts.get('Medium',0)}, Low={counts.get('Low',0)}",
        "",
        "TOP FINDINGS (sorted by severity):",
    ]
    for v in top:
        lines.append(
            f"  [{v['severity']}] {v['name']} | Host: {v['host']} | CVE: {v['cve']}"
        )
        if v["solution"]:
            lines.append(f"    -> Fix: {v['solution']}")

    return "\n".join(lines)


def summarize_trend(reports_data):
    """Multi-report trend payload for Gemini."""
    lines = [f"TREND ANALYSIS — LAST {len(reports_data)} REPORTS", ""]
    for r in reports_data:
        counts = Counter(v["severity"] for v in r["vulns"])
        score  = calculate_score(counts, len(r["vulns"]))
        letter = score_to_letter(score)
        lines.append(f"Report: {r['filename']}  |  Date: {r['date']}  |  Grade: {letter} ({score}/100)")
        lines.append(
            f"  Critical={counts.get('Critical',0)}, High={counts.get('High',0)}, "
            f"Medium={counts.get('Medium',0)}, Low={counts.get('Low',0)}, "
            f"Total={len(r['vulns'])}"
        )
        lines.append("")
    return "\n".join(lines)


# ─── AI PROMPTS ───────────────────────────────────────────────────────────────

SINGLE_REPORT_PROMPT = """
You are Vulnerd, a helpful and friendly security analysis assistant. Your job is to turn
vulnerability scan data into a clear, professional security report card that is easy to
understand and act on.

Your tone is warm, encouraging, and supportive — like a knowledgeable colleague who wants
to help the team succeed. You are honest about risks, but never alarmist or condescending.
When findings are serious, you explain why calmly and focus on the solution. When things
are going well, you acknowledge it genuinely.

Think of this as a traditional security report blended with a school report card —
structured, professional, grades included, with a helpful instructor's note at the end.

Format EXACTLY as follows. Plain text only — no markdown, no asterisks, no bullet dashes:

EXECUTIVE SUMMARY
[2-3 sentences. A clear, calm overview of the current security posture based on this scan.
Mention the grade, the total finding count, and the most important area to focus on.]

KEY FINDINGS
[The most significant vulnerabilities from this scan, starting with the highest severity.
For each finding: what it is, what risk it introduces, and what resolving it would do for
the environment. Keep the language informative, not alarming. If there are no critical
findings, say so positively and describe what was found instead.]

CONTRIBUTING FACTORS
[What patterns in the data suggest about the environment — patching cadence, configuration
practices, or areas that may benefit from additional attention. Frame this constructively,
as observations rather than criticism.]

RECOMMENDATIONS
[A numbered, prioritized action list. Clear and specific — what to address first, what can
follow, and why the order matters. Each item should feel achievable, not overwhelming.
Write these as instructions the reader can hand to their IT team or security vendor.]

THREAT CONTEXT
[For the top 3-5 findings, explain what these vulnerabilities mean in the real world.
Who actually exploits them — ransomware groups, automated botnets, nation-state actors?
What does a real attack using this vulnerability look like? What is the business consequence
if it is exploited — data loss, downtime, regulatory exposure, financial impact?
Be specific and grounded. The goal is to help a non-technical reader understand
the stakes clearly enough to prioritize and communicate upward.]

WHO TO CALL
[Based on the findings in this report, what kind of help does this organization need?
Be specific: should they contact their managed IT provider, an incident response firm,
their internal security team, a patch management vendor? What should they specifically
ask for — an emergency patching window, a configuration audit, a penetration test?
Frame this as a practical next step the reader can take today, not a general suggestion.]

INSTRUCTOR'S NOTE
[A short, friendly closing paragraph. Acknowledge what the team is doing well, highlight
the one area that will make the biggest difference, and end on an encouraging note.
This should feel like it was written by someone who is rooting for them to improve.]
"""

TREND_PROMPT = """
You are Vulnerd, a helpful and friendly security analysis assistant. You are reviewing
multiple vulnerability scans over time to help a team understand their security progress.

Your tone is warm, encouraging, and data-driven. You celebrate genuine improvement, identify
patterns with care, and frame all feedback constructively. Think of this as a semester
progress report — honest, professional, and written by someone who wants the student to succeed.

Format EXACTLY as follows. Plain text only — no markdown, no asterisks, no bullet dashes:

PROGRESS SUMMARY
[A clear overview of the trend across all scans. Is the environment improving, holding
steady, or showing new areas of concern? Mention the grade trajectory and frame it
in terms of the team's effort and direction.]

SCAN-BY-SCAN REVIEW
[Walk through each report chronologically. For each: note the grade, what changed from
the prior scan, and what that change suggests. Acknowledge improvements explicitly
and describe increases in findings as opportunities to address.]

PATTERNS TO ADDRESS
[Findings that appear across multiple scans. Explain why recurring items are worth
prioritizing and suggest what kind of process or practice change would resolve them
over time. Frame this as coaching, not criticism.]

AREAS OF IMPROVEMENT
[What has genuinely gotten better across the scans? Specific reductions in severity
categories, resolved findings, or positive trends. Be specific and acknowledge the work.]

RECOMMENDED NEXT STEPS
[Program-level recommendations — process improvements, policy suggestions, or team
practices that would help sustain or accelerate improvement. Frame these as instructions
the reader can bring to their IT team or security vendor, not technical tasks to do themselves.]

THREAT CONTEXT
[Based on the recurring and highest-severity findings across these scans, what does the
threat landscape actually look like for this organization? What kinds of attackers target
these vulnerability types — opportunistic botnets, ransomware groups, targeted actors?
What is the realistic business consequence if these exposures are exploited over time?
Help the reader understand what continued exposure means in practical terms.]

WHO TO CALL
[Given the trend data, what kind of ongoing support does this organization need?
Should they engage a managed security provider, schedule regular patching reviews with
their IT vendor, bring in an external auditor? What specifically should they ask for?
Make this concrete enough that a non-technical manager can act on it immediately.]

PROGRESS REPORT COMMENT
[A warm, encouraging closing paragraph. Summarize the trajectory, acknowledge the effort,
and give the team a clear, motivating picture of what success looks like in the next scan.]
"""

def analyze_with_gemini(summary_text, trend_mode=False):
    """Sends the formatted summary to Gemini. Returns clean plain text."""
    if not GEMINI_API_KEY:
        print("[!] No GEMINI_API_KEY in .env — AI analysis skipped.")
        return "AI analysis unavailable. Add GEMINI_API_KEY to your .env file."

    print("[*] Running analysis...")
    try:
        client = google_genai.Client(api_key=GEMINI_API_KEY)
        system = TREND_PROMPT if trend_mode else SINGLE_REPORT_PROMPT
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=summary_text,
            config=google_genai.types.GenerateContentConfig(
                system_instruction=system,
                max_output_tokens=2000,
            )
        )
        text = response.text
        for char in ["**", "## ", "# ", "- "]:
            text = text.replace(char, "")
        return text.strip()
    except Exception as e:
        print(f"[!] Gemini error: {e}")
        return "AI analysis could not be completed at this time. Please check your API key and try again."


# ─── PDF GENERATOR ────────────────────────────────────────────────────────────

ALL_SECTION_HEADERS = {
    # Single report
    "EXECUTIVE SUMMARY", "KEY FINDINGS", "CONTRIBUTING FACTORS",
    "RECOMMENDATIONS", "THREAT CONTEXT", "WHO TO CALL", "INSTRUCTOR'S NOTE",
    # Trend report
    "PROGRESS SUMMARY", "SCAN-BY-SCAN REVIEW", "PATTERNS TO ADDRESS",
    "AREAS OF IMPROVEMENT", "RECOMMENDED NEXT STEPS", "THREAT CONTEXT",
    "WHO TO CALL", "PROGRESS REPORT COMMENT",
}

GRADE_COLORS = {
    "A":  colors.HexColor("#1a7a1a"),
    "A-": colors.HexColor("#2d8a2d"),
    "B+": colors.HexColor("#4a7c1a"),
    "B":  colors.HexColor("#6b8e23"),
    "B-": colors.HexColor("#8b9a1a"),
    "C+": colors.HexColor("#b8860b"),
    "C":  colors.HexColor("#cc8800"),
    "C-": colors.HexColor("#cc6600"),
    "D+": colors.HexColor("#cc4400"),
    "D":  colors.HexColor("#cc2200"),
    "D-": colors.HexColor("#aa0000"),
    "F":  colors.HexColor("#880000"),
}


def generate_pdf(analysis_text, report_meta, output_path):
    """
    Generates the Vulnerd Report Card PDF.
    report_meta keys: filename, hash, total, counts, score, letter, commentary, trend_grades
    """
    print("[*] Printing your report card...")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=page_letter,
        leftMargin=0.85 * inch,
        rightMargin=0.85 * inch,
        topMargin=0.85 * inch,
        bottomMargin=0.85 * inch,
    )
    styles = getSampleStyleSheet()
    story  = []

    # ── Styles
    title_style = ParagraphStyle(
        "vtitle", parent=styles["Heading1"],
        fontSize=20, spaceAfter=2,
        textColor=colors.HexColor("#0a0a0a"),
        fontName="Helvetica-Bold"
    )
    subtitle_style = ParagraphStyle(
        "vsub", parent=styles["Normal"],
        fontSize=10, spaceAfter=2,
        textColor=colors.HexColor("#444444"),
        fontName="Helvetica"
    )
    meta_style = ParagraphStyle(
        "vmeta", parent=styles["Normal"],
        fontSize=8, spaceAfter=3,
        textColor=colors.HexColor("#666666"),
        fontName="Courier"
    )
    section_style = ParagraphStyle(
        "vsection", parent=styles["Heading2"],
        fontSize=11, spaceBefore=14, spaceAfter=4,
        textColor=colors.HexColor("#1a1a2e"),
        fontName="Helvetica-Bold"
    )
    body_style = ParagraphStyle(
        "vbody", parent=styles["Normal"],
        fontSize=10, leading=15, spaceAfter=5,
        textColor=colors.HexColor("#1a1a1a"),
        fontName="Helvetica"
    )
    commentary_style = ParagraphStyle(
        "vcommentary", parent=styles["Normal"],
        fontSize=10, leading=14, spaceAfter=6,
        textColor=colors.HexColor("#2a2a4a"),
        fontName="Helvetica-Oblique",
        leftIndent=8, rightIndent=8
    )

    # ── Header
    story.append(Paragraph("VULNERD SECURITY REPORT CARD", title_style))
    story.append(Paragraph(
        f"Automated Vulnerability Analysis  |  {datetime.now().strftime('%B %d, %Y')}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2,
                             color=colors.HexColor("#0a0a0a"), spaceAfter=8))
    story.append(Paragraph(f"Source: {report_meta.get('filename', 'N/A')}", meta_style))
    story.append(Paragraph(f"SHA-256: {report_meta.get('hash', 'N/A')}", meta_style))
    story.append(Spacer(1, 0.15 * inch))

    # ── Grade block (single report)
    score  = report_meta.get("score")
    letter = report_meta.get("letter")

    if score is not None and letter is not None:
        grade_color = GRADE_COLORS.get(letter, colors.HexColor("#333333"))
        counts = report_meta.get("counts", {})
        total  = report_meta.get("total", 0)

        grade_cell_text = (
            f'<font size="42" color="white"><b>{letter}</b></font><br/>'
            f'<font size="14" color="white">{score}/100</font>'
        )

        breakdown_data = [
            ["Severity",  "Count", "Deduction"],
            ["Critical",  str(counts.get("Critical", 0)), f"-{counts.get('Critical',0)*20} pts"],
            ["High",      str(counts.get("High",     0)), f"-{counts.get('High',0)*8} pts"],
            ["Medium",    str(counts.get("Medium",   0)), f"-{counts.get('Medium',0)*3} pts"],
            ["Low",       str(counts.get("Low",      0)), f"-{counts.get('Low',0)*1} pt"],
            ["TOTAL",     str(total),                     f"Score: {score}/100"],
        ]

        breakdown_table = Table(breakdown_data,
                                colWidths=[1.2*inch, 0.8*inch, 1.2*inch])
        breakdown_table.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1, 0),  colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 9),
            ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.HexColor("#f5f5f5"), colors.white]),
            ("BACKGROUND",     (0, -1), (-1, -1), colors.HexColor("#e8e8e8")),
            ("FONTNAME",       (0, -1), (-1, -1), "Helvetica-Bold"),
            ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING",     (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ]))

        grade_para = Paragraph(grade_cell_text,
                               ParagraphStyle("grade_cell", alignment=1, leading=20))

        outer_table = Table([[grade_para, breakdown_table]],
                            colWidths=[1.4*inch, None])
        outer_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0),  grade_color),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (0, 0), (0, 0),  "CENTER"),
            ("LEFTPADDING",   (0, 0), (0, 0),  10),
            ("RIGHTPADDING",  (0, 0), (0, 0),  10),
            ("TOPPADDING",    (0, 0), (0, 0),  14),
            ("BOTTOMPADDING", (0, 0), (0, 0),  14),
            ("LEFTPADDING",   (1, 0), (1, 0),  14),
            ("BOX",           (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
        ]))
        story.append(outer_table)
        story.append(Spacer(1, 0.12 * inch))

        # Commentary box
        commentary = report_meta.get("commentary", "")
        if commentary:
            commentary_box = Table(
                [[Paragraph(f'"{commentary}"', commentary_style)]],
                colWidths=[doc.width]
            )
            commentary_box.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#f0f0f8")),
                ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#aaaacc")),
                ("LEFTPADDING",   (0,0), (-1,-1), 10),
                ("RIGHTPADDING",  (0,0), (-1,-1), 10),
                ("TOPPADDING",    (0,0), (-1,-1), 8),
                ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ]))
            story.append(commentary_box)
            story.append(Spacer(1, 0.15 * inch))

    # ── Trend grade history table
    trend_grades = report_meta.get("trend_grades")
    if trend_grades:
        story.append(Paragraph("GRADE HISTORY", section_style))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#cccccc"), spaceAfter=4))
        tg_data = [["Report", "Date", "Findings", "Score", "Grade"]]
        for tg in trend_grades:
            tg_data.append([
                tg["filename"][:35],
                tg["date"],
                str(tg["total"]),
                f"{tg['score']}/100",
                tg["letter"],
            ])
        tg_table = Table(tg_data,
                         colWidths=[2.3*inch, 1.0*inch, 0.8*inch, 0.8*inch, 0.6*inch])
        tg_table.setStyle(TableStyle([
            ("BACKGROUND",     (0,0), (-1,0),  colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("ALIGN",          (1,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f5f5f5"), colors.white]),
            ("GRID",           (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING",     (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
        ]))
        story.append(tg_table)
        story.append(Spacer(1, 0.15 * inch))

    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#cccccc"), spaceAfter=6))

    # ── Analysis body
    for line in analysis_text.splitlines():
        stripped = line.strip()
        if not stripped:
            story.append(Spacer(1, 0.04 * inch))
        elif stripped in ALL_SECTION_HEADERS:
            story.append(Paragraph(stripped, section_style))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor("#cccccc"), spaceAfter=2))
        else:
            safe = (stripped
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))
            story.append(Paragraph(safe, body_style))

    # ── Footer
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        f"Generated by Vulnerd v5.0  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"Data source: {report_meta.get('filename', 'N/A')}",
        ParagraphStyle("footer", parent=styles["Normal"],
                       fontSize=7, textColor=colors.HexColor("#999999"),
                       fontName="Helvetica", spaceBefore=4)
    ))

    doc.build(story)
    return output_path


# ─── EMAIL ────────────────────────────────────────────────────────────────────

def send_email(recipient, pdf_path, score=None, letter=None):
    """Emails the report card. Subject line includes the grade."""
    if not EMAIL_SENDER or not EMAIL_PASSWORD:
        print("[!] Email credentials missing from .env — skipping.")
        return

    grade_line = f" — Grade: {letter} ({score}/100)" if score is not None and letter else ""
    print(f"[*] Sending report to {recipient}...")

    msg            = EmailMessage()
    msg["Subject"] = f"Vulnerd Security Report Card{grade_line}  |  {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"]    = EMAIL_SENDER
    msg["To"]      = recipient

    body_grade = f"Final Grade: {letter} ({score}/100)\n\n" if score is not None and letter else ""
    msg.set_content(
        f"Your Vulnerd Security Report Card is attached.\n\n"
        f"{body_grade}"
        "Detailed analysis, remediation priorities, and a remediation script are inside.\n\n"
        "— Vulnerd Engine\n"
        "  Automated Security Report Card System"
    )

    try:
        with open(pdf_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                               filename=os.path.basename(pdf_path))
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"[!] Email failed: {e}")


# ─── PIPELINE ─────────────────────────────────────────────────────────────────

def run_single_report(csv_file):
    print(f"[*] Reading scan file...")
    file_hash = sha256(csv_file)
    vulns     = parse_nessus_csv(csv_file)

    if not vulns:
        print("[!] No actionable vulnerabilities found in this file.")
        return None, None, None

    counts     = Counter(v["severity"] for v in vulns)
    score      = calculate_score(counts, len(vulns))
    letter     = score_to_letter(score)
    commentary = grade_commentary(letter)

    print(f"[*] Analyzing findings...")
    summary  = summarize_vulns(vulns, score, letter)
    analysis = analyze_with_gemini(summary, trend_mode=False)

    print(f"[*] Building report card...")
    out_name = f"Vulnerd_ReportCard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = os.path.join(REPORT_DIR, out_name)

    meta = {
        "filename":    os.path.basename(csv_file),
        "hash":        file_hash,
        "total":       len(vulns),
        "counts":      counts,
        "score":       score,
        "letter":      letter,
        "commentary":  commentary,
        "trend_grades": None,
    }
    generate_pdf(analysis, meta, out_path)
    return out_path, score, letter


def run_trend_analysis(csv_files):
    files = csv_files[:5]
    print(f"[*] Loading {len(files)} scan files...")

    reports_data = []
    trend_grades = []

    for f in files:
        vulns  = parse_nessus_csv(f)
        counts = Counter(v["severity"] for v in vulns)
        score  = calculate_score(counts, len(vulns))
        letter = score_to_letter(score)
        mtime  = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%Y-%m-%d")

        reports_data.append({"filename": os.path.basename(f), "date": mtime, "vulns": vulns})
        trend_grades.append({
            "filename": os.path.basename(f),
            "date":     mtime,
            "total":    len(vulns),
            "score":    score,
            "letter":   letter,
        })

    print(f"[*] Analyzing trends...")
    summary  = summarize_trend(reports_data)
    analysis = analyze_with_gemini(summary, trend_mode=True)

    print(f"[*] Building report card...")
    out_name = f"Vulnerd_TrendReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = os.path.join(REPORT_DIR, out_name)

    meta = {
        "filename":    f"Trend — {len(files)} reports",
        "hash":        "N/A (multi-file analysis)",
        "score":       None,
        "letter":      None,
        "commentary":  None,
        "trend_grades": trend_grades,
    }
    generate_pdf(analysis, meta, out_path)
    return out_path, None, None


# ─── UTILS ────────────────────────────────────────────────────────────────────

def get_csv_files():
    files = glob.glob(os.path.join(EVIDENCE_DIR, "*.csv"))
    files.sort(key=os.path.getmtime, reverse=True)
    return files

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_dirs():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print("=" * 54)
    print("   VULNERD v5.0 — SECURITY REPORT CARD ENGINE")
    print("   Your network's GPA, delivered to your inbox.")
    print("=" * 54)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    clear()
    ensure_dirs()
    banner()

    csv_files = get_csv_files()

    if not csv_files:
        print(f"\n[!] No scan files found in {EVIDENCE_DIR}/")
        print("[*] Drop your Nessus .csv exports there and re-run.")
        return

    print(f"\n[*] Found {len(csv_files)} scan file(s).")
    print(f"    Most recent: {os.path.basename(csv_files[0])}\n")
    print("What would you like to do?")
    print("  1. Grade the most recent scan")
    if len(csv_files) >= 2:
        print(f"  2. Trend analysis — last {min(len(csv_files), 5)} scans")
    print("  3. Exit\n")

    choice = input("Select (1/2/3): ").strip()

    if choice == "3":
        print("\nDone.")
        return

    if choice not in ("1", "2"):
        print("[!] Invalid choice.")
        return

    if choice == "2" and len(csv_files) < 2:
        print("[!] Need at least 2 scan files for trend analysis.")
        return

    email = input("\nSend report card to: ").strip()
    if not email:
        print("[!] An email address is required.")
        return

    print("\n" + "-" * 54)

    if choice == "1":
        pdf_path, score, letter = run_single_report(csv_files[0])
    else:
        pdf_path, score, letter = run_trend_analysis(csv_files)

    if pdf_path:
        send_email(email, pdf_path, score, letter)

    print("-" * 54)
    if pdf_path and letter:
        print(f"\n[+] Done. Grade: {letter} ({score}/100) — report sent to {email}")
    elif pdf_path:
        print(f"\n[+] Done. Report sent to {email}")
    print()

if __name__ == "__main__":
    main()
