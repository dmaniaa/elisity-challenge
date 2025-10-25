# Challenge for Elisity recruitment process - Log Analysis Tool
This tool analyzes a supplied log file to identify potential security events.
App is deployed at https://elisity.danielmania.com/

# Implemented event types
## Bruteforce attack
- Triggered by at least two failed login attempts from the same IP address within 3 seconds.
## SQL Injection Attempt
- Triggered by log entries indicating SQL injection attempts, detected by software providing the logs.
## Unusual Access
- Triggered by log entries that deviate from normal patterns, based on detected events from logs.
## Port Scan
- Triggered by connection attempts to different ports on the server, detected by software providing the logs.
## Unauthorized Request
- Triggered by log entries with HTTP status codes 401 or 403, indicating unauthorized access attempts

# Usage
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the Flask app: `python main.py`
4. Access the web interface at `http://localhost:5050` (default port, can be changed in main.py or via environment variable PORT)
5. Upload a log file to analyze and view the results on the web page.

Or
1. Build and deploy the Docker container using the provided Dockerfile and docker-compose.yml.
2. Access the web interface at `http://localhost:5050` (default port, can be changed in docker-compose.yml).

# Note
This tool is only for recruitment purposes, meant to analyze a specific format, and must not be used in production environments.