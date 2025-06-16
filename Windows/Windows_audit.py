import win32evtlog
import platform
import subprocess
import os
import psutil
from tabulate import tabulate
from datetime import datetime

EVENT_LEVELS = {
    1: ("Critical", win32evtlog.EVENTLOG_ERROR_TYPE),
    2: ("Error", win32evtlog.EVENTLOG_ERROR_TYPE),
    3: ("Warning", win32evtlog.EVENTLOG_WARNING_TYPE),
    4: ("Information", win32evtlog.EVENTLOG_INFORMATION_TYPE),
    5: ("Verbose", win32evtlog.EVENTLOG_INFORMATION_TYPE)
}

def get_system_info():
    return {
        "Hostname": platform.node(),
        "OS": platform.system(),
        "Release": platform.release(),
        "Architecture": platform.machine(),
        "Processor": platform.processor()
    }

def list_users():
    try:
        users = psutil.users()
        return [f"{u.name} ({u.host})" for u in users]
    except Exception as e:
        return [f"Error: {e}"]

def check_admin_users():
    try:
        result = subprocess.check_output(['net', 'localgroup', 'Administrators'], stderr=subprocess.DEVNULL).decode()
        return result.strip().split('\n')[4:-2]  # Trim header/footer
    except Exception as e:
        return [f"Error: {e}"]

def check_updates():
    return ["Use PowerShell: Get-WindowsUpdate or check Windows Update GUI."]

def check_firewall():
    try:
        result = subprocess.check_output(['powershell', '-Command', 'Get-NetFirewallProfile | Format-Table Name, Enabled'], stderr=subprocess.DEVNULL).decode()
        return result.strip().split('\n')
    except Exception as e:
        return [f"Error: {e}"]

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
                    message[:100] + '...' if len(message) > 100 else message
                ])
                if len(events_data) >= max_events:
                    win32evtlog.CloseEventLog(hand)
                    return events_data
    win32evtlog.CloseEventLog(hand)
    return events_data

def main():
    print("\n📋 ISO 27001 Windows Audit Report")
    print(tabulate(get_system_info().items(), tablefmt='fancy_grid', headers=["Parameter", "Value"]))

    print("\n👥 Logged-in Users (A.9.2.3)")
    print("\n".join(list_users()))

    print("\n🔐 Admin Users (A.9.2.3)")
    print("\n".join(check_admin_users()))

    print("\n🛡️ Firewall Status (A.13.1.1)")
    print("\n".join(check_firewall()))

    print("\n📦 Patch Status (A.12.6.1)")
    print("\n".join(check_updates()))

    print("\n🧠 Choose Event Log Level to Inspect:")
    for num, (label, _) in EVENT_LEVELS.items():
        print(f"{num}: {label}")
    try:
        choice = int(input("Enter level number (or 0 for all): ").strip())
    except ValueError:
        choice = 0

    label, level_code = EVENT_LEVELS.get(choice, ("All", None))

    for log in ['System', 'Application', 'Security']:
        print(f"\n📘 {log} Log – {label} Events:")
        logs = read_event_log(log_type=log, level_filter=level_code)
        headers = ["Event ID", "Time", "Source", "Category", "Type", "Message"]
        print(tabulate(logs, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()