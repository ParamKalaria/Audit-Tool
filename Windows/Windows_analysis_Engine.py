import win32evtlog
from tabulate import tabulate

# Define event IDs of interest
EVENT_CATEGORIES = {
    "Authentication Failures": [4625],  # Failed logon
    "Account Lockouts": [4740],
    "Service Failures": [7031, 7034],   # Service terminated unexpectedly
    "Critical Errors": [1000, 1001],    # App crashes
    "Audit Failures": [5038, 6281]      # Security audit failures
}

def analyze_event_log(log_type='System', max_events=200):
    hand = win32evtlog.OpenEventLog('localhost', log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    findings = []

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for event in events:
            for category, ids in EVENT_CATEGORIES.items():
                if event.EventID in ids:
                    message = " | ".join(event.StringInserts) if event.StringInserts else ""
                    findings.append([
                        category,
                        log_type,
                        event.EventID,
                        event.TimeGenerated.Format(),
                        event.SourceName,
                        message[:100] + '...' if len(message) > 100 else message
                    ])
            if len(findings) >= max_events:
                win32evtlog.CloseEventLog(hand)
                return findings
    win32evtlog.CloseEventLog(hand)
    return findings

def main():
    all_findings = []
    for log in ['System', 'Application', 'Security']:
        all_findings.extend(analyze_event_log(log_type=log))

    if all_findings:
        headers = ["Category", "Log", "Event ID", "Time", "Source", "Message"]
        print("\n🔍 Potential Issues Detected:")
        print(tabulate(all_findings, headers=headers, tablefmt="fancy_grid"))
    else:
        print("✅ No known issues detected in the scanned logs.")

if __name__ == "__main__":
    main()