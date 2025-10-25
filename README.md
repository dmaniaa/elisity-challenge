# Challenge for Elisity recruitment process - Log Analysis Tool
This tool analyzes a supplied log file to identify potential security events.

# Implemented event types
## Bruteforce attack
- Triggered by at least two failed login attempts from the same IP address within 3 seconds.
## SQL Injection Attempt
- Triggered by log entries indicating SQL injection attempts, detected by software providing the logs.
## Unusual Access
- Triggered by log entries that deviate from normal patterns, based on detected events and HTTP codes indicating denied access.
## Port Scan
- Triggered by connection attempts to different ports on the server, detected by software providing the logs.