import datetime
from enum import Enum

class EventCategory(Enum):
    BRUTEFORCE = "Bruteforce attempt"
    SQL_INJECTION = "SQL Injection attempt"
    UNUSUAL_ACCESS = "Unusual Access attempt"
    PORT_SCAN = "Port Scan"

class LogEntry:
    def __init__(self, timestamp, level, source, event, message):
        self.timestamp = datetime.datetime.strptime(timestamp, "[%Y-%m-%d %H:%M:%S]")
        self.level = level
        self.source = source
        self.event = event
        self.message = message
        self.category = None
    
class BruteForceEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.level = log_entry.level
        self.source = log_entry.source
        self.category = EventCategory.BRUTEFORCE
        self.username = log_entry.message.split("user=")[1]
    def __str__(self):
        return f"{self.timestamp} | Source IP: {self.source} | Triggered filter: {self.category.value} | Username: {self.username}"
    
class SQLInjectionEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.level = log_entry.level
        self.source = log_entry.source
        self.category = EventCategory.SQL_INJECTION
        self.user_input = log_entry.message.split("user_input=")[1]
    def __str__(self):
        return f"{self.timestamp} | Source IP: {self.source} | Triggered filter: {self.category.value} | User Input: {self.user_input}"
    
class UnusualAccessEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.level = log_entry.level
        self.source = log_entry.source
        self.category = EventCategory.UNUSUAL_ACCESS
        if log_entry.event == "UNUSUAL_ACCESS":
            self.path = log_entry.message
            self.code = None
            self.method = None
        if log_entry.event == "GET" or log_entry.event == "POST":
            self.path = log_entry.message.split(" ")[0]
            self.code = log_entry.message.split(" ")[1]
            self.method = log_entry.event
    def __str__(self):
        return f"{self.timestamp} | Source IP: {self.source} | Triggered filter: {self.category.value} | Path: {self.path} | Code returned: {self.code} | Method logged: {self.method}"

class PortScanEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.level = log_entry.level
        self.source = log_entry.source
        self.category = EventCategory.PORT_SCAN
        self.port = log_entry.message.split("target=")[1]
    def __str__(self):
        return f"{self.timestamp}| Source IP: {self.source} | Triggered filter: {self.category.value} | Port: {self.port}"


def analyze_log_file():
    log_entries = []

    #odczyt i parsowanie wpisów do klasy
    with open("sample_security.log", "r") as file:
        logfile_lines = file.readlines()
        for line in logfile_lines:
            line.strip()
            timestamp = line.split()[0] + " " + line.split()[1]
            level = line.split()[2]
            source = line.split()[3]
            event = line.split()[4]
            message = " ".join(line.split()[5:])
            log_entry = LogEntry(timestamp, level, source, event, message)
            log_entries.append(log_entry)

    interesting_entries = []

    #oznaczenie wpisów z kodami 401, 403, typami wskazującymi na atak lub poziomem powyzej INFO
    interesting_codes = ["401", "403"]
    interesting_events = ["FAILED_LOGIN", "SQL_INJECTION_ATTEMPT", "UNUSUAL_ACCESS", "PORT_SCAN_ATTEMPT"]

    for entry in log_entries:
        if any(code in entry.message for code in interesting_codes):
            interesting_entries.append(entry)
        elif entry.event in interesting_events:
            interesting_entries.append(entry)
        elif entry.level in ["ERROR", "WARNING"]:
            interesting_entries.append(entry)

    failed_logins = []
    bruteforce_entries = []
    sql_injection_entries = []
    unusual_access_entries = []
    port_scan_entries = []

    for entry in interesting_entries:
        if entry.event == "FAILED_LOGIN":
            failed_logins.append(entry)
            if len(failed_logins) >= 2 and (failed_logins[-1].timestamp - failed_logins[-2].timestamp).seconds <= 3:
                bruteforce_entries.append(BruteForceEvent(entry))
        else:
            failed_logins.clear()
        if entry.event == "SQL_INJECTION_ATTEMPT":
            sql_injection_entries.append(SQLInjectionEvent(entry))
        if entry.event == "UNUSUAL_ACCESS":
            unusual_access_entries.append(UnusualAccessEvent(entry))
        if entry.event == "PORT_SCAN_ATTEMPT":
            port_scan_entries.append(PortScanEvent(entry))
        if any(code in entry.message for code in interesting_codes):
            unusual_access_entries.append(UnusualAccessEvent(entry))

    return [bruteforce_entries, sql_injection_entries, unusual_access_entries, port_scan_entries]

for entry in analyze_log_file():
    print("------")
    for subentry in entry:
        print(subentry)