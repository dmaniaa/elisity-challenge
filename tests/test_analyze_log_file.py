import datetime
from src.analyze_log_file import analyze_log_file, BruteForceEvent, SQLInjectionEvent, UnusualAccessEvent, PortScanEvent

def test_analyze_log_file():
    try:
        with open("test_log.log", "w") as f:
            f.write("[2025-10-25 10:50:00] WARNING 10.0.0.1 FAILED_LOGIN user=admin\n")
            f.write("[2025-10-25 10:50:01] WARNING 10.0.0.1 FAILED_LOGIN user=admin\n")
            f.write("[2025-10-25 10:50:02] WARNING 10.0.0.1 FAILED_LOGIN user=admin\n")
            f.write("[2025-10-25 11:00:00] ERROR 10.0.10.5 SQL_INJECTION_ATTEMPT user_input=' OR '1'='1\n")
            f.write("[2025-10-25 11:05:00] ERROR 10.5.10.5 UNUSUAL_ACCESS /etc/passwd\n")
            f.write("[2025-10-25 11:05:01] INFO 10.5.10.5 GET /admin 403\n")
            f.write("[2025-10-25 11:10:00] WARNING 192.168.0.50 PORT_SCAN_ATTEMPT target=22\n")
    except:
        assert False, "Failed to create test log file."

    result = analyze_log_file("test_log.log")
    assert result is not None
    assert len(result) == 4  
    assert len(result[0]) == 1
    assert len(result[1]) == 1
    assert len(result[2]) == 2
    assert len(result[3]) == 1
    assert isinstance(result[0][0], BruteForceEvent)
    assert isinstance(result[1][0], SQLInjectionEvent)
    assert isinstance(result[2][0], UnusualAccessEvent)
    assert isinstance(result[2][1], UnusualAccessEvent)
    assert isinstance(result[3][0], PortScanEvent)
    assert result[0][0].timestamp == datetime.datetime(2025, 10, 25, 10, 50, 1)
    assert result[0][0].source == "10.0.0.1"
    assert result[0][0].username == "admin"
    assert result[1][0].timestamp == datetime.datetime(2025, 10, 25, 11, 0, 0)
    assert result[1][0].source == "10.0.10.5"
    assert result[1][0].user_input == "' OR '1'='1"
    assert result[2][0].timestamp == datetime.datetime(2025, 10, 25, 11, 5, 0)
    assert result[2][0].source == "10.5.10.5"
    assert result[2][0].path == "/etc/passwd"
    assert result[2][0].code is None
    assert result[2][0].method is None
    assert result[2][1].timestamp == datetime.datetime(2025, 10, 25, 11, 5, 1)
    assert result[2][1].source == "10.5.10.5"
    assert result[2][1].path == "/admin"
    assert result[2][1].code == "403"
    assert result[2][1].method == "GET"
    assert result[3][0].timestamp == datetime.datetime(2025, 10, 25, 11, 10, 0)
    assert result[3][0].source == "192.168.0.50"
    assert result[3][0].port == "22"
