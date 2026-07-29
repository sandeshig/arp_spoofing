"""
exporter.py
===========
Generates the "Reports" tab output: Network Summary, Device Summary,
Detected Threats, ARP Statistics, and an Attack Timeline chart, exported
as PDF, CSV, or TXT.

PDF generation uses reportlab (Platypus, for nice flowing tables and
headings). CSV/TXT exports are simple and dependency-free so they always
work even in the most minimal environment.
"""

import csv
import os
import tempfile
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak,
)

import database
import graph
from utils import now_iso

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


def _ensure_reports_dir():
    """
    Purpose:
        Make sure the reports/ output directory exists before writing.
    Parameters:
        None
    Returns:
        None
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)


def _gather_report_data(network_info: dict):
    """
    Purpose:
        Pull every piece of data the report needs from the database in one
        place, so the PDF/CSV/TXT builders all work from the same snapshot.
    Parameters:
        network_info (dict): current network context (host IP, gateway,
            adapter, hostname, etc.) supplied by the caller (main.py has
            this readily available from scanner.py).
    Returns:
        dict: {
            'network_info': dict,
            'devices': list[sqlite3.Row],
            'alerts': list[sqlite3.Row],
            'category_counts': list[sqlite3.Row],
            'severity_counts': dict,
            'generated_at': str,
        }
    """
    devices = database.db.get_all_devices()
    alerts = database.db.get_recent_alerts(limit=1000)
    category_counts = database.db.alert_category_counts()
    severity_counts = {
        "info": database.db.count_alerts("info"),
        "warning": database.db.count_alerts("warning"),
        "critical": database.db.count_alerts("critical"),
    }
    return {
        "network_info": network_info,
        "devices": devices,
        "alerts": alerts,
        "category_counts": category_counts,
        "severity_counts": severity_counts,
        "generated_at": now_iso(),
    }


# -------------------------------------------------------------------------- #
# PDF export
# -------------------------------------------------------------------------- #
def export_pdf(network_info: dict, filename: str = None) -> str:
    """
    Purpose:
        Build a full PDF security report: network summary, device summary,
        detected threats table, ARP statistics, and an attack timeline chart.
    Parameters:
        network_info (dict): current network context (see _gather_report_data).
        filename (str|None): output filename; auto-generated with a
                              timestamp if not provided.
    Returns:
        str: full path to the generated PDF file.
    """
    _ensure_reports_dir()
    data = _gather_report_data(network_info)
    filename = filename or f"ARP_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(REPORTS_DIR, filename)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleDark", parent=styles["Title"], textColor=colors.HexColor("#1c1c1c"))
    heading_style = ParagraphStyle("HeadingDark", parent=styles["Heading2"], textColor=colors.HexColor("#2c3e50"),
                                    spaceBefore=14, spaceAfter=6)
    normal_style = styles["Normal"]

    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    story = []

    # --- Title page ---
    story.append(Paragraph("Real-Time ARP Spoofing Detection", title_style))
    story.append(Paragraph("LAN Intrusion Monitoring - Security Report", styles["Heading3"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated: {data['generated_at']}", normal_style))
    story.append(Spacer(1, 20))

    # --- Network summary ---
    story.append(Paragraph("1. Network Summary", heading_style))
    net = data["network_info"]
    net_table_data = [["Field", "Value"]] + [[k, str(v)] for k, v in net.items()]
    net_table = Table(net_table_data, colWidths=[6 * cm, 9 * cm])
    net_table.setStyle(_default_table_style())
    story.append(net_table)

    # --- Device summary ---
    story.append(Paragraph("2. Device Summary", heading_style))
    devices = data["devices"]
    story.append(Paragraph(f"Total devices known: {len(devices)}", normal_style))
    device_rows = [["IP", "MAC", "Vendor", "Status", "Authorized", "Last Seen"]]
    for d in devices[:60]:  # cap table length; full list also available via CSV export
        device_rows.append([
            d["ip"], d["mac"], d["vendor"] or "Unknown",
            d["status"], "Yes" if d["authorized"] else "No", d["last_seen"],
        ])
    device_table = Table(device_rows, colWidths=[2.6 * cm, 3.4 * cm, 3 * cm, 1.8 * cm, 2 * cm, 3 * cm])
    device_table.setStyle(_default_table_style())
    story.append(device_table)

    # --- Detected threats ---
    story.append(PageBreak())
    story.append(Paragraph("3. Detected Threats", heading_style))
    alerts = data["alerts"]
    story.append(Paragraph(
        f"Total alerts: {len(alerts)} &nbsp;|&nbsp; "
        f"Critical: {data['severity_counts']['critical']} &nbsp;|&nbsp; "
        f"Warning: {data['severity_counts']['warning']} &nbsp;|&nbsp; "
        f"Info: {data['severity_counts']['info']}",
        normal_style,
    ))
    story.append(Spacer(1, 8))
    alert_rows = [["Time", "Severity", "Category", "IP", "Message"]]
    for a in alerts[:80]:
        alert_rows.append([
            a["timestamp"][11:19], a["severity"].upper(), a["category"],
            a["ip"] or "-", Paragraph(a["message"], normal_style),
        ])
    alert_table = Table(alert_rows, colWidths=[2 * cm, 2.2 * cm, 3 * cm, 2.3 * cm, 5.5 * cm])
    alert_table.setStyle(_default_table_style())
    story.append(alert_table)

    # --- Charts ---
    story.append(PageBreak())
    story.append(Paragraph("4. ARP Statistics & Charts", heading_style))
    tmp_dir = tempfile.mkdtemp(prefix="arp_report_")

    pie_path = os.path.join(tmp_dir, "severity_pie.png")
    graph.save_figure(graph.build_alert_severity_pie(data["severity_counts"]), pie_path)
    story.append(Image(pie_path, width=10 * cm, height=8 * cm))

    if data["category_counts"]:
        bar_path = os.path.join(tmp_dir, "category_bar.png")
        graph.save_figure(graph.build_category_bar_chart(data["category_counts"]), bar_path)
        story.append(Image(bar_path, width=14 * cm, height=9 * cm))

    story.append(Paragraph("5. Attack Timeline", heading_style))
    if alerts:
        timeline_path = os.path.join(tmp_dir, "timeline.png")
        # alerts_timeline is chronological (ASC); get_recent_alerts is DESC, so reverse it here.
        chronological = list(reversed(alerts))
        graph.save_figure(graph.build_attack_timeline(chronological), timeline_path)
        story.append(Image(timeline_path, width=16 * cm, height=8 * cm))
    else:
        story.append(Paragraph("No alerts recorded during this session.", normal_style))

    doc.build(story)
    return path


def _default_table_style() -> TableStyle:
    """
    Purpose:
        Shared table styling for consistent report tables.
    Parameters:
        None
    Returns:
        reportlab.platypus.TableStyle
    """
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f7")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ])


# -------------------------------------------------------------------------- #
# CSV export
# -------------------------------------------------------------------------- #
def export_csv(network_info: dict, filename: str = None) -> str:
    """
    Purpose:
        Export the current alerts table as a CSV file (spreadsheet-friendly
        format for further analysis).
    Parameters:
        network_info (dict): unused for CSV but accepted for a consistent
                              call signature with export_pdf/export_txt.
        filename (str|None): output filename; auto-generated if not provided.
    Returns:
        str: full path to the generated CSV file.
    """
    _ensure_reports_dir()
    alerts = database.db.get_recent_alerts(limit=5000)
    filename = filename or f"ARP_Alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    path = os.path.join(REPORTS_DIR, filename)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "severity", "category", "ip", "mac", "message"])
        for a in alerts:
            writer.writerow([a["timestamp"], a["severity"], a["category"], a["ip"], a["mac"], a["message"]])
    return path


# -------------------------------------------------------------------------- #
# TXT export
# -------------------------------------------------------------------------- #
def export_txt(network_info: dict, filename: str = None) -> str:
    """
    Purpose:
        Export a plain-text summary report (readable without any special
        software - useful for quick incident notes or emailing).
    Parameters:
        network_info (dict): current network context.
        filename (str|None): output filename; auto-generated if not provided.
    Returns:
        str: full path to the generated TXT file.
    """
    _ensure_reports_dir()
    data = _gather_report_data(network_info)
    filename = filename or f"ARP_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path = os.path.join(REPORTS_DIR, filename)

    lines = []
    lines.append("=" * 70)
    lines.append("REAL-TIME ARP SPOOFING DETECTION - SECURITY REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {data['generated_at']}")
    lines.append("")
    lines.append("-- NETWORK SUMMARY --")
    for k, v in data["network_info"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append(f"-- DEVICE SUMMARY ({len(data['devices'])} known devices) --")
    for d in data["devices"]:
        lines.append(
            f"  {d['ip']:<16} {d['mac']:<18} {d['vendor'] or 'Unknown':<20} "
            f"{d['status']:<8} Authorized={'Yes' if d['authorized'] else 'No':<3} Last seen={d['last_seen']}"
        )
    lines.append("")
    sev = data["severity_counts"]
    lines.append(f"-- DETECTED THREATS ({len(data['alerts'])} total | "
                 f"critical={sev['critical']} warning={sev['warning']} info={sev['info']}) --")
    for a in data["alerts"]:
        lines.append(f"  [{a['timestamp']}] {a['severity'].upper():<9} {a['category']:<18} "
                      f"{a['ip'] or '-':<15} {a['message']}")
    lines.append("")
    lines.append("-- END OF REPORT --")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def export(fmt: str, network_info: dict, filename: str = None) -> str:
    """
    Purpose:
        Single dispatch entry point used by the GUI's "Export Report"
        button so callers don't need to know the individual function names.
    Parameters:
        fmt (str): 'pdf' | 'csv' | 'txt'.
        network_info (dict): current network context.
        filename (str|None): optional output filename override.
    Returns:
        str: path to the generated file.
    Raises:
        ValueError: if fmt is not one of the supported formats.
    """
    fmt = fmt.lower().strip()
    if fmt == "pdf":
        return export_pdf(network_info, filename)
    if fmt == "csv":
        return export_csv(network_info, filename)
    if fmt == "txt":
        return export_txt(network_info, filename)
    raise ValueError(f"Unsupported export format: {fmt}")
