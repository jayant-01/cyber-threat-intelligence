# Domain Reconnaissance AI Agent

This tool is designed to help security researchers and bug bounty hunters gather information about target domains. It automates the process of collecting publicly available information and known vulnerabilities.

## Features

- Domain WHOIS information gathering
- DNS record enumeration
- Subdomain discovery
- Technology stack detection
- Known vulnerability scanning
- SSL/TLS certificate analysis
- Historical data collection
- Security headers analysis
- Open ports and services detection

## Prerequisites

- Python 3.8 or higher
- API keys for various services (Shodan, VirusTotal, Censys)

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Create a `.env` file with your API keys:
```
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
```

## Usage

```bash
python domain_recon.py --domain example.com
```

## Legal Disclaimer

This tool is for educational and legitimate security research purposes only. Always:
- Obtain proper authorization before testing any domain
- Follow responsible disclosure practices
- Respect rate limits and terms of service of APIs
- Do not use for malicious purposes

## Output

The tool generates a comprehensive report including:
- Domain information
- Known vulnerabilities
- Security misconfigurations
- Technology stack details
- Recommendations for security improvements 