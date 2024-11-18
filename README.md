# Website Security Scanner

This tool is a comprehensive security scanner designed to assess websites for common vulnerabilities and misconfigurations. The scanner checks for critical security measures, potential vulnerabilities, and misconfigurations that could expose a website to risks. It offers a wide range of checks, including HTTP headers, SSL/TLS configuration, CSRF protection, common vulnerabilities, sensitive information disclosure, and more.

## Features
- **HTTP Headers Check**: Verifies security headers like X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy, and others.
- **CSRF Protection**: Checks for the presence of CSRF tokens to protect against cross-site request forgery.
- **Clickjacking Protection**: Detects whether the website is protected against clickjacking attacks.
- **Sensitive Information Disclosure**: Scans the website for exposure of sensitive information such as passwords, API keys, and private data.
- **Subdomain Takeover**: Identifies if any subdomains are vulnerable to takeover.
- **API Security**: Analyzes the API for proper security settings and CORS headers.
- **SSL/TLS Configuration**: Assesses the website’s SSL/TLS setup, ensuring secure connections.
- **Common Vulnerabilities**: Checks for XSS, SQL injection, command injection, and directory traversal vulnerabilities.
- **Open Redirects**: Identifies open redirects that could potentially lead to malicious websites.

## Requirements
- Python 3.x
- `requests` module
- `beautifulsoup4` module
- `dnspython` module
- `ssl` and `socket` (standard libraries)

## Installation
1. Clone or download the repository.
2. Install the required modules:
    ```bash
    pip install requests beautifulsoup4 dnspython
    ```
3. Run the script using:
    ```bash
    python website_security_scanner.py
    ```
4. Enter the website URL when prompted, and the scanner will generate a detailed security report.

## Usage
Simply run the script and input the URL of the website you want to scan. The script will automatically assess the security of the website and generate a detailed JSON report.

```bash
Enter the website URL (e.g., http://example.com): https://yourwebsite.com
