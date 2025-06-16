import win32evtlog
from tabulate import tabulate

EVENT_LEVELS = {
    "Critical": win32evtlog.EVENTLOG_ERROR_TYPE,     # Windows doesn't have a separate Critical
    "Error": win32evtlog.EVENTLOG_ERROR_TYPE,
    "Warning": win32evtlog.EVENTLOG_WARNING_TYPE,
    "Information": win32evtlog.EVENTLOG_INFORMATION_TYPE,
    "Verbose": win32evtlog.EVENTLOG_INFORMATION_TYPE  # Windows doesn't label as Verbose
}

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
    print("Choose Event Log Level:")
    for level in EVENT_LEVELS:
        print(f"- {level}")
    user_choice = input("Enter level: ").strip().capitalize()
    level_code = EVENT_LEVELS.get(user_choice)

    if not level_code:
        print("⚠️ Invalid choice. Showing all event types.")
        level_code = None

    for log_type in ['System', 'Application', 'Security']:
        print(f"\n📘 {log_type} Log – {user_choice or 'All'} Events:")
        logs = read_event_log(log_type=log_type, level_filter=level_code)
        headers = ["Event ID", "Time", "Source", "Category", "Type", "Message"]
        print(tabulate(logs, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()