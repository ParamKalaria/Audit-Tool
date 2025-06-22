import win32evtlog
import platform
import subprocess
import os
import psutil
from tabulate import tabulate
from datetime import datetime

# Map log severity levels to win32 constants
EVENT_LEVELS = {
    1: ("Critical", win32evtlog.EVENTLOG_ERROR_TYPE),
    2: ("Error", win32evtlog.EVENTLOG_ERROR_TYPE),
    3: ("Warning", win32evtlog.EVENTLOG_WARNING_TYPE),
    4: ("Information", win32evtlog.EVENTLOG_INFORMATION_TYPE),
    5: ("Verbose", win32evtlog.EVENTLOG_INFORMATION_TYPE)
}

# Collect system metadata
def get_system_info():
    return {
        "Hostname": platform.node(),
        "OS": platform.system(),
        "Release": platform.release(),
        "Architecture": platform.machine(),
        "Processor": platform.processor()
    }

# Logged-in users
def list_users():
    try:
        return [f"{u.name} ({u.host})" for u in psutil.users()]
    except Exception as e:
        return [f"Error: {e}"]

# Local administrators
def check_admin_users():
    try:
        result = subprocess.check_output(['net', 'localgroup', 'Administrators'], stderr=subprocess.DEVNULL).decode()
        return result.strip().split('\n')[4:-2]
    except Exception as e:
        return [f"Error: {e}"]

# Patch management (stub)
def check_updates():
    return ["Use PowerShell: Get-WindowsUpdate or check Windows Update GUI."]

# Firewall status
def check_firewall():
    try:
        result = subprocess.check_output(
            ['powershell', '-Command', 'Get-NetFirewallProfile | Format-Table Name, Enabled'],
            stderr=subprocess.DEVNULL
        ).decode()
        return result.strip().split('\n')
    except Exception as e:
        return [f"Error: {e}"]

# Windows event log reader
def read_event_log(log_type='System', level_filter=None, max_events=50):
    hand = win32evtlog.OpenEventLog('localhost', log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events_data = []
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            if level_filter is None or event.EventType == level_filter:
                message = " | ".join(event.StringInserts) if event.StringInserts else ""
                events_data.append([
                    event.EventID,
                    event.TimeGenerated.Format(),
                    event.SourceName,
                    event.EventCategory,
                    event.EventType,
                    message  # Full message retained
                ])
                if len(events_data) >= max_events:
                    win32evtlog.CloseEventLog(hand)
                    return events_data
    win32evtlog.CloseEventLog(hand)
    return events_data

# HTML report output
def export_to_html(report_data, event_log_tables, filename="audit_report.html"):
    html = ['<html><head><title>ISO 27001 Audit Report</title>']
    html.append('<style>body{font-family:Arial;} table{border-collapse:collapse;width:100%;margin-bottom:30px;} th,td{border:1px solid #ccc;padding:8px;text-align:left;} th{background:#f2f2f2;} h2{color:#2E5C6E;}</style>')
    html.append('</head><body>')
    html.append(f"<h1>ISO 27001 Windows Audit Report</h1>")
    html.append(f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")

    for section_title, items in report_data:
        html.append(f"<h2>{section_title}</h2>")
        html.append("<table><tr><th>#</th><th>Detail</th></tr>")
        for idx, line in enumerate(items, 1):
            html.append(f"<tr><td>{idx}</td><td>{line}</td></tr>")
        html.append("</table>")

    for log_title, rows in event_log_tables:
        html.append(f"<h2>{log_title}</h2>")
        html.append("<table>")
        html.append("<tr><th>Event ID</th><th>Time</th><th>Source</th><th>Category</th><th>Type</th><th>Message</th></tr>")
        for row in rows:
            html.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
        html.append("</table>")

    html.append("</body></html>")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print(f"\n✅ HTML report saved to: {filename}")

# Main execution flow
def main():
    print("\n📋 ISO 27001 Windows Audit Report")
    report_data = []
    event_log_tables = []

    sys_info = get_system_info()
    print(tabulate(sys_info.items(), tablefmt='fancy_grid', headers=["Parameter", "Value"]))
    report_data.append(("System Info", [f"{k}: {v}" for k, v in sys_info.items()]))

    print("\n👥 Logged-in Users (A.9.2.3)")
    users = list_users()
    print("\n".join(users))
    report_data.append(("Logged-in Users (A.9.2.3)", users))

    print("\n🔐 Admin Users (A.9.2.3)")
    admins = check_admin_users()
    print("\n".join(admins))
    report_data.append(("Admin Users (A.9.2.3)", admins))

    print("\n🛡️ Firewall Status (A.13.1.1)")
    fw_status = check_firewall()
    print("\n".join(fw_status))
    report_data.append(("Firewall Status (A.13.1.1)", fw_status))

    print("\n📦 Patch Status (A.12.6.1)")
    patch_info = check_updates()
    print("\n".join(patch_info))
    report_data.append(("Patch Status (A.12.6.1)", patch_info))

    print("\n🧠 Choose Event Log Level to Inspect:")
    for num, (label, _) in EVENT_LEVELS.items():
        print(f"{num}: {label}")
    try:
        choice = int(input("Enter level number (or 0 for all): ").strip())
    except ValueError:
        choice = 0
    label, level_code = EVENT_LEVELS.get(choice, ("All", None))

    for log_type in ['System', 'Application', 'Security']:
        print(f"\n📘 {log_type} Log – {label} Events:")
        logs = read_event_log(log_type=log_type, level_filter=level_code)
        print(tabulate(logs, headers=["Event ID", "Time", "Source", "Category", "Type", "Message"], tablefmt="fancy_grid"))
        event_log_tables.append((f"{log_type} Log – {label} Events", logs))

    export_to_html(report_data, event_log_tables)

if __name__ == "__main__":
    main()