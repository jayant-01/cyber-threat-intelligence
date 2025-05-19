#!/usr/bin/env python3

import os
import sys
import json
import argparse
import requests
import whois
import dns.resolver
import virustotal_python
import ssl
import socket
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from dotenv import load_dotenv
from tqdm import tqdm
from OpenSSL import SSL
from urllib.parse import urlparse
import OpenSSL
import google.generativeai as genai

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class DomainReconnaissance:
    def __init__(self, domain):
        self.domain = domain.replace("http://", "").replace("https://", "").strip("/")
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.results = {}
        load_dotenv()
        self.setup_api_keys()

    def setup_api_keys(self):
        """Setup API keys from environment variables"""
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')

    def print_section(self, title):
        """Print a section header"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

    def get_whois(self):
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
            print(f"{Fore.GREEN}[+] WHOIS information retrieved{Style.RESET_ALL}")
            return w
        except Exception as e:
            print(f"{Fore.RED}[-] Error retrieving WHOIS: {e}{Style.RESET_ALL}")
            return {}

    def get_dns_records(self):
        """Get DNS records for domain"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
                print(f"{Fore.GREEN}[+] {record_type} records retrieved{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error retrieving {record_type} records: {e}{Style.RESET_ALL}")
        
        self.results['dns'] = records
        return records

    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.domain)
            conn.connect((self.domain, 443))
            
            # Get the certificate
            cert = conn.getpeercert()
            cipher = conn.cipher()
            protocol = conn.version()
            
            # Extract certificate information using OpenSSL for more details
            try:
                pem_cert = ssl.get_server_certificate((self.domain, 443))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
                
                # Get certificate information
                issuer = x509.get_issuer().get_components()
                issuer_str = ', '.join(f"{name[0].decode('utf-8')}={name[1].decode('utf-8')}" for name in issuer)
                
                subject = x509.get_subject().get_components()
                subject_str = ', '.join(f"{name[0].decode('utf-8')}={name[1].decode('utf-8')}" for name in subject)
                
                # Format dates
                not_before = x509.get_notBefore().decode('utf-8')
                not_after = x509.get_notAfter().decode('utf-8')
                
                # Get signature algorithm
                sig_alg = x509.get_signature_algorithm().decode('utf-8')
                
                has_expired = x509.has_expired()
                
            except Exception as e:
                print(f"{Fore.RED}[-] Error parsing certificate with OpenSSL: {e}{Style.RESET_ALL}")
                # Fallback to basic cert info
                issuer_str = str(cert.get('issuer', []))
                subject_str = str(cert.get('subject', []))
                not_before = str(cert.get('notBefore', ''))
                not_after = str(cert.get('notAfter', ''))
                sig_alg = 'Unknown'
                has_expired = False
            
            ssl_info = {
                'subject': subject_str,
                'issuer': issuer_str,
                'version': cert.get('version', 'Unknown'),
                'not_before': not_before,
                'not_after': not_after,
                'signature_algorithm': sig_alg,
                'protocol': protocol,
                'cipher': f"{cipher[0]}-{cipher[1]}-{cipher[2]} bits"
            }
            
            # Check for vulnerabilities
            vulnerabilities = []
            
            # Check protocol version
            if protocol in ['SSLv2', 'SSLv3']:
                vulnerabilities.append(f"Insecure protocol {protocol} detected")
            
            if protocol in ['TLSv1', 'TLSv1.1']:
                vulnerabilities.append(f"Outdated protocol {protocol} detected")
            
            # Check for weak ciphers
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
            for weak in weak_ciphers:
                if weak in cipher[0]:
                    vulnerabilities.append(f"Weak cipher {weak} detected")
            
            # Check certificate expiry
            if has_expired:
                vulnerabilities.append("Certificate has expired")
            
            # Check if using SHA1 (weak)
            if 'sha1' in sig_alg.lower():
                vulnerabilities.append("Certificate uses weak SHA1 signature")
            
            print(f"{Fore.GREEN}[+] SSL/TLS information retrieved{Style.RESET_ALL}")
            
            return ssl_info, vulnerabilities
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking SSL/TLS: {e}{Style.RESET_ALL}")
            return {}, []

    def check_security_headers(self):
        """Check security headers"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        security_headers = {
            'Strict-Transport-Security': {'value': 'Not Set', 'status': 'danger'},
            'Content-Security-Policy': {'value': 'Not Set', 'status': 'danger'},
            'X-Content-Type-Options': {'value': 'Not Set', 'status': 'danger'},
            'X-Frame-Options': {'value': 'Not Set', 'status': 'danger'},
            'X-XSS-Protection': {'value': 'Not Set', 'status': 'danger'},
            'Referrer-Policy': {'value': 'Not Set', 'status': 'danger'},
            'Permissions-Policy': {'value': 'Not Set', 'status': 'danger'},
            'Cache-Control': {'value': 'Not Set', 'status': 'warning'}
        }
        
        try:
            resp = requests.get(f"https://{self.domain}", headers=headers, timeout=10, verify=True)
            
            for header in security_headers.keys():
                if header.lower() in resp.headers:
                    security_headers[header]['value'] = resp.headers[header.lower()]
                    security_headers[header]['status'] = 'good'
        
        except requests.exceptions.SSLError:
            try:
                resp = requests.get(f"http://{self.domain}", headers=headers, timeout=10)
                
                for header in security_headers.keys():
                    if header.lower() in resp.headers:
                        security_headers[header]['value'] = resp.headers[header.lower()]
                        security_headers[header]['status'] = 'warning'  # Downgrade due to HTTP
            except Exception as e:
                print(f"{Fore.RED}[-] Error checking HTTP: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking HTTPS: {e}{Style.RESET_ALL}")
        
        self.results['security_headers'] = security_headers
        return security_headers

    def check_virustotal(self):
        """Check domain on VirusTotal"""
        if not self.virustotal_api_key:
            print(f"{Fore.YELLOW}[!] VirusTotal API key not found{Style.RESET_ALL}")
            return {}
            
        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{self.domain}",
                headers=headers
            )
            
            if response.status_code == 200:
                self.results['virustotal'] = response.json()
                print(f"{Fore.GREEN}[+] VirusTotal information retrieved{Style.RESET_ALL}")
                return response.json()
            else:
                print(f"{Fore.RED}[-] VirusTotal API error: {response.status_code}{Style.RESET_ALL}")
                return {}
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking VirusTotal: {e}{Style.RESET_ALL}")
            return {}

    def check_shodan(self):
        """Check domain on Shodan - currently disabled due to API limitations"""
        print("[!] Shodan integration disabled")
        return {}

    def run(self):
        """Run all reconnaissance"""
        print(f"\n{Fore.CYAN}Starting reconnaissance on {self.domain}{Style.RESET_ALL}\n")
        
        whois_info = self.get_whois()
        dns_info = self.get_dns_records()
        ssl_info, ssl_vulnerabilities = self.check_ssl_tls()
        security_headers = self.check_security_headers()
        virustotal_info = self.check_virustotal()
        shodan_info = self.check_shodan()
        
        self.results = {
            'domain': self.domain,
            'whois': whois_info,
            'dns': dns_info,
            'ssl': ssl_info,
            'ssl_vulnerabilities': ssl_vulnerabilities,
            'security_headers': security_headers,
            'virustotal': virustotal_info,
            'shodan': shodan_info
        }
        
        return self.results

def generate_ai_insights(domain, data):
    """Generate AI insights using Google's Gemini API"""
    try:
        # Configure Gemini API
        genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
        
        # Initialize the model
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        # Convert data to JSON string with datetime handling
        data_json = json.dumps(data, cls=DateTimeEncoder, indent=2)
        
        # Prepare the prompt
        prompt = f"""As a cybersecurity expert, analyze the following domain reconnaissance data for {domain} and provide detailed security insights:

{data_json}

Please provide a comprehensive analysis including:
1. Key Security Findings
   - List all significant security observations
   - Highlight any critical vulnerabilities
   - Note any unusual configurations

2. Risk Assessment
   - Evaluate the overall security posture
   - Identify potential attack vectors
   - Assess the impact of identified vulnerabilities

3. Recommendations
   - Provide specific, actionable security improvements
   - Prioritize recommendations based on risk level
   - Include best practices for each finding

4. Notable Patterns
   - Identify any suspicious patterns
   - Note any security misconfigurations
   - Highlight any positive security measures

Format the response in clear sections with bullet points and use markdown formatting for better readability."""

        # Generate insights using Gemini
        response = model.generate_content(prompt)
        
        # Extract the text from the response
        if response.text:
            return response.text
        else:
            return "No insights could be generated at this time."

    except Exception as e:
        logger.error(f"Error generating AI insights: {str(e)}")
        return f"Error generating AI insights: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='Domain Reconnaissance Tool')
    parser.add_argument('--domain', required=True, help='Target domain to analyze')
    args = parser.parse_args()

    recon = DomainReconnaissance(args.domain)
    results = recon.run()
    
    # Print results in a formatted way
    print("\nResults:")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 