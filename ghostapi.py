import os
import re
import json
import requests
import concurrent.futures
from urllib.parse import urlparse

# Report structure
report = {
    "endpoints": [],
    "vulnerabilities": [],
    "sensitive_data": [],
    "summary": {}
}

# Blocklist for endpoints that shouldn't be checked
blocklist = [
    "https://devguide.python.org",
    "www.gnu.org/licenses/",
    "devguide.python.org",
    "learn.microsoft.com",
    "www.visualstudio.com"
]

# Headers for basic security testing
security_headers = {
    "Strict-Transport-Security": "HTTP Strict Transport Security (HSTS) not implemented",
    "X-Content-Type-Options": "X-Content-Type-Options header not present",
    "X-Frame-Options": "X-Frame-Options header missing",
    "X-XSS-Protection": "X-XSS-Protection header missing",
    "Content-Security-Policy": "Content-Security-Policy (CSP) not implemented",
    "Access-Control-Allow-Origin": "CORS misconfiguration (Access-Control-Allow-Origin header is too permissive)"
}

# HTTP methods to test
http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

# Vulnerability payloads
vulnerability_payloads = {
    "sql_injection": ["' OR 1=1 --", "' UNION SELECT NULL --"],
    "xss": ['<script>alert(1)</script>', '"><script>alert(1)</script>'],
    "command_injection": ['; ls', '&& whoami']
}

# Sensitive information patterns
sensitive_info_patterns = {
    "api_key": r"(?i)(api[_-]?key|token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]+)['\"]?",
    "password": r"(?i)(password|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9\-_!@#$%^&*]+)['\"]?",
    "username": r"(?i)(username|user)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]+)['\"]?",
    "auth_token": r"(?i)(auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]+)['\"]?"
}

# Create "api_loot" directory if it doesn't exist
def create_loot_directory():
    loot_directory = "api_loot"
    if not os.path.exists(loot_directory):
        os.makedirs(loot_directory)
    return loot_directory

# Function to check if an endpoint is in the blocklist
def is_blocked(endpoint):
    for blocked in blocklist:
        if blocked in endpoint:
            return True
    return False

# Load API files from a directory and search for potential vulnerabilities
def load_api_from_directory(directory_path):
    print(f"[INFO] Crawling directory: {directory_path}")
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".json") or file.endswith(".txt"):  # Assuming APIs are in JSON or TXT files
                print(f"[INFO] Checking file: {file_path}")
                scan_file_for_apis_and_sensitive_data(file_path)

    if not report['endpoints']:
        print("[INFO] No API endpoints found in the directory.")
    else:
        print(f"[INFO] {len(report['endpoints'])} API endpoints loaded for testing.")

# Scan file for APIs and sensitive information
def scan_file_for_apis_and_sensitive_data(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()

        # Search for API endpoints
        api_endpoints = re.findall(r"https?://[^\s\"\'<>]+", content)
        for endpoint in api_endpoints:
            if not is_blocked(endpoint):  # Only add if not blocked
                report['endpoints'].append(endpoint)

        # Search for sensitive information
        for info_type, pattern in sensitive_info_patterns.items():
            matches = re.findall(pattern, content)
            for match in matches:
                report['sensitive_data'].append({
                    "type": info_type,
                    "file": file_path,
                    "match": match
                })

# Test for security headers
def check_security_headers(response):
    for header, message in security_headers.items():
        if header not in response.headers:
            report['vulnerabilities'].append({
                "type": "Missing Security Header",
                "endpoint": response.url,
                "message": message,
                "poc": f"Perform a GET request to {response.url} and observe that the '{header}' is missing."
            })

# Test for real SQL Injection vulnerabilities
def test_sql_injection(endpoint, params):
    for payload in vulnerability_payloads['sql_injection']:
        injected_params = {key: payload for key in params}
        try:
            response = requests.get(endpoint, params=injected_params, timeout=10)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                report['vulnerabilities'].append({
                    "type": "SQL Injection",
                    "endpoint": endpoint,
                    "message": f"SQL Injection detected with payload: {payload}",
                    "poc": f"Use the following SQL Injection payload: {payload} on {endpoint}"
                })
        except requests.RequestException:
            pass

# Test for real XSS vulnerabilities
def test_xss(endpoint, params):
    for payload in vulnerability_payloads['xss']:
        injected_params = {key: payload for key in params}
        try:
            response = requests.get(endpoint, params=injected_params, timeout=10)
            if payload in response.text:
                report['vulnerabilities'].append({
                    "type": "XSS (Cross-Site Scripting)",
                    "endpoint": endpoint,
                    "message": f"XSS detected with payload: {payload}",
                    "poc": f"Inject the following XSS payload: {payload} on {endpoint}"
                })
        except requests.RequestException:
            pass

# Test for command injection vulnerabilities
def test_command_injection(endpoint, params):
    for payload in vulnerability_payloads['command_injection']:
        injected_params = {key: payload for key in params}
        try:
            response = requests.get(endpoint, params=injected_params, timeout=10)
            if "root" in response.text.lower() or "bin" in response.text.lower():
                report['vulnerabilities'].append({
                    "type": "Command Injection",
                    "endpoint": endpoint,
                    "message": f"Command Injection detected with payload: {payload}",
                    "poc": f"Inject the following Command Injection payload: {payload} on {endpoint}"
                })
        except requests.RequestException:
            pass

# Test API for authentication and rate limiting mechanisms
def check_authentication_and_rate_limiting(response):
    if response.status_code == 401:
        report['vulnerabilities'].append({
            "type": "Missing Authentication",
            "endpoint": response.url,
            "message": "API requires authentication",
            "poc": f"Perform a request to {response.url} without authentication and observe a 401 Unauthorized response."
        })

    # Test if rate limiting headers exist
    if 'X-RateLimit-Limit' not in response.headers:
        report['vulnerabilities'].append({
            "type": "Missing Rate Limiting",
            "endpoint": response.url,
            "message": "API does not seem to enforce rate limiting.",
            "poc": f"Send multiple requests to {response.url} and observe if rate limiting is enforced."
        })

# Perform the API test on multiple HTTP methods
def test_api_endpoint(endpoint):
    try:
        parsed_url = urlparse(endpoint)
        params = dict([part.split('=') for part in parsed_url.query.split('&') if '=' in part])
        
        # Test security headers
        response = requests.get(endpoint, timeout=10)
        check_security_headers(response)

        # Test for SQL Injection, XSS, and Command Injection vulnerabilities
        if params:
            test_sql_injection(endpoint, params)
            test_xss(endpoint, params)
            test_command_injection(endpoint, params)

        # Check for authentication and rate limiting
        check_authentication_and_rate_limiting(response)

    except requests.RequestException as e:
        report['vulnerabilities'].append({
            "type": "Request Failure",
            "endpoint": endpoint,
            "message": f"Request failed due to: {str(e)}"
        })

# Generate the report and store findings in the "api_loot" folder
def generate_report(loot_directory):
    endpoint_count = len(report['endpoints'])
    vulnerability_count = len(report['vulnerabilities'])
    sensitive_data_count = len(report['sensitive_data'])

    report['summary'] = {
        "Total Endpoints Scanned": endpoint_count,
        "Total Vulnerabilities Found": vulnerability_count,
        "Sensitive Data Found": sensitive_data_count
    }

    # Save detailed report to JSON file
    report_path = os.path.join(loot_directory, "api_security_report.json")
    with open(report_path, 'w') as report_file:
        json.dump(report, report_file, indent=4)

    # Save endpoints to a separate file
    endpoints_path = os.path.join(loot_directory, "endpoints.txt")
    with open(endpoints_path, 'w') as endpoints_file:
        for endpoint in report['endpoints']:
            endpoints_file.write(f"{endpoint}\n")

    # Save sensitive data to a separate file
    sensitive_data_path = os.path.join(loot_directory, "sensitive_data.txt")
    with open(sensitive_data_path, 'w') as sensitive_data_file:
        for data in report['sensitive_data']:
            sensitive_data_file.write(f"File: {data['file']}, Type: {data['type']}, Match: {data['match']}\n")

    # Save vulnerabilities to a separate file
    vulnerabilities_path = os.path.join(loot_directory, "vulnerabilities.txt")
    with open(vulnerabilities_path, 'w') as vulnerabilities_file:
        for vulnerability in report['vulnerabilities']:
            vulnerabilities_file.write(
                f"Type: {vulnerability['type']}, "
                f"Endpoint: {vulnerability['endpoint']}, "
                f"Message: {vulnerability['message']}, "
                f"PoC: {vulnerability.get('poc', 'No PoC available')}\n"
            )

    print(f"[INFO] API Security Report generated at: {report_path}")

# Main function
def main():
    # Step 1: Ask the user for a directory path to crawl
    directory_path = input("Enter the directory path to crawl for API files: ").strip()
    
    if not os.path.exists(directory_path):
        print(f"[ERROR] Directory path {directory_path} not found!")
        return
    
    # Step 2: Load API files and extract endpoints and sensitive data
    load_api_from_directory(directory_path)

    if not report['endpoints']:
        print("[INFO] No API endpoints found for testing.")
        return

    # Step 3: Run security checks on all endpoints
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_api_endpoint, report['endpoints'])

    # Step 4: Create "api_loot" folder to store findings
    loot_directory = create_loot_directory()

    # Step 5: Generate the detailed report with PoC
    generate_report(loot_directory)

if __name__ == "__main__":
    main()
