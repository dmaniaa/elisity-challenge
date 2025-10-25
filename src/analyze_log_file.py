import datetime
import os

#bazowa klasa wpisu logu - przed analizą i określeniem kategorii
class LogEntry:
    def __init__(self, timestamp, level, source, event, message):
        self.timestamp = datetime.datetime.strptime(timestamp, "[%Y-%m-%d %H:%M:%S]")
        self.level = level
        self.source = source
        self.event = event
        self.message = message
    
 #klasy pochodne dla konkretnych kategorii zdarzeń   
class BruteForceEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.source = log_entry.source
        self.username = log_entry.message.split("user=")[1]

class SQLInjectionEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.source = log_entry.source
        self.user_input = log_entry.message.split("user_input=")[1]
    
class UnusualAccessEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.source = log_entry.source
        if log_entry.event == "UNUSUAL_ACCESS":
            self.path = log_entry.message
            self.code = None
            self.method = None
        if log_entry.event == "GET" or log_entry.event == "POST":
            self.path = log_entry.message.split(" ")[0]
            self.code = log_entry.message.split(" ")[1]
            self.method = log_entry.event

class PortScanEvent(LogEntry):
    def __init__(self, log_entry):
        self.timestamp = log_entry.timestamp
        self.source = log_entry.source
        self.port = log_entry.message.split("target=")[1]


def analyze_log_file(filename):
    log_entries = []
    #odczyt i parsowanie wpisów do klasy
    try:
        with open(filename, "r") as file:
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
        os.remove(filename)
    except:
        return None

    interesting_entries = []

    #oznaczenie wpisów z kodami 401, 403 oraz typami wskazującymi na atak lub poziomem powyzej INFO
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

    #sortowanie wpisów według rodzaju do odpowiednich klas
    for entry in interesting_entries:
        if entry.event == "FAILED_LOGIN":
            failed_logins.append(entry)
            if len(failed_logins) >= 2 and (failed_logins[-1].timestamp - failed_logins[-2].timestamp).seconds <= 3 and failed_logins[-1].source == failed_logins[-2].source:
                bruteforce_entries.append(BruteForceEvent(entry))
                failed_logins.clear()
        if entry.event == "SQL_INJECTION_ATTEMPT":
            sql_injection_entries.append(SQLInjectionEvent(entry))
        if entry.event == "UNUSUAL_ACCESS":
            unusual_access_entries.append(UnusualAccessEvent(entry))
        if entry.event == "PORT_SCAN_ATTEMPT":
            port_scan_entries.append(PortScanEvent(entry))
        if any(code in entry.message for code in interesting_codes):
            unusual_access_entries.append(UnusualAccessEvent(entry))
        else:
            continue

    return [bruteforce_entries, sql_injection_entries, unusual_access_entries, port_scan_entries]
