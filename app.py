import os
import logging
import requests
import httpx
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from bs4 import BeautifulSoup
import re
import json
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import concurrent.futures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("vulnerability_scanner")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Form for URL submission
class ScanForm(FlaskForm):
    url = StringField('Website URL', validators=[DataRequired(), URL()])
    submit = SubmitField('Scan Website')

# Test payloads for different vulnerabilities
SQL_INJECTION_PAYLOADS = [
    "'", 
    "1' OR '1'='1", 
    "' OR 1=1 --", 
    "' OR '1'='1' --", 
    "admin' --", 
    "1'; DROP TABLE users; --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')"
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//google.com%2F@evil.com",
    "/\\evil.com"
]

# Security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HTTP Strict Transport Security (HSTS)',
    'Content-Security-Policy': 'Content Security Policy (CSP)',
    'X-Content-Type-Options': 'X-Content-Type-Options',
    'X-Frame-Options': 'X-Frame-Options',
    'X-XSS-Protection': 'X-XSS-Protection',
    'Referrer-Policy': 'Referrer-Policy',
    'Permissions-Policy': 'Permissions-Policy (formerly Feature-Policy)'
}

class VulnerabilityScanner:
    def __init__(self, base_url, max_urls=30):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.urls_to_scan = [base_url]
        self.forms = []
        self.max_urls = max_urls
        self.results = {
            'sql_injection': [],
            'xss': [],
            'open_redirect': [],
            'missing_headers': {},
            'info': {
                'scanned_urls': 0,
                'forms_tested': 0,
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': '',
                'scan_duration': ''
            }
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def crawl(self):
        """Crawl the website to find all internal links and forms"""
        logger.info(f"Starting crawl of {self.base_url}")
        
        while self.urls_to_scan and len(self.visited_urls) < self.max_urls:
            url = self.urls_to_scan.pop(0)
            if url in self.visited_urls:
                continue
                
            logger.info(f"Crawling: {url}")
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                self.visited_urls.add(url)
                
                # Check security headers on the main page
                if len(self.visited_urls) == 1:
                    self.check_security_headers(response.headers)
                
                # Parse the HTML content
                soup = BeautifulSoup(response.text, 'lxml')
                
                # Find all links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Only add internal links
                    if urlparse(full_url).netloc == self.base_domain and full_url not in self.visited_urls:
                        self.urls_to_scan.append(full_url)
                
                # Find all forms
                for form in soup.find_all('form'):
                    form_info = {
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'get').lower(),
                        'inputs': []
                    }
                    
                    # Find all input fields
                    for input_field in form.find_all(['input', 'textarea']):
                        input_type = input_field.get('type', '')
                        if input_type.lower() not in ['submit', 'button', 'image', 'reset']:
                            form_info['inputs'].append({
                                'name': input_field.get('name', ''),
                                'type': input_type
                            })
                    
                    self.forms.append(form_info)
                    
            except Exception as e:
                logger.error(f"Error crawling {url}: {str(e)}")
        
        self.results['info']['scanned_urls'] = len(self.visited_urls)
        logger.info(f"Completed crawling. Found {len(self.visited_urls)} URLs and {len(self.forms)} forms.")
    
    def check_security_headers(self, headers):
        """Check for missing security headers"""
        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                self.results['missing_headers'][header] = description
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        logger.info("Testing for SQL injection vulnerabilities")
        
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'].lower() in ['text', 'search', 'password', '']:
                    for payload in SQL_INJECTION_PAYLOADS:
                        try:
                            data = {input_field['name']: payload}
                            
                            if form['method'] == 'post':
                                response = self.session.post(form['action'], data=data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=data, timeout=10)
                            
                            # Check for SQL error patterns
                            sql_errors = [
                                "SQL syntax", "mysql_fetch", "ORA-", "Oracle error",
                                "Microsoft SQL Server", "PostgreSQL", "SQLite", "syntax error"
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in response.text.lower():
                                    self.results['sql_injection'].append({
                                        'url': form['action'],
                                        'method': form['method'],
                                        'field': input_field['name'],
                                        'payload': payload,
                                        'error': error
                                    })
                                    break
                                    
                        except Exception as e:
                            logger.error(f"Error testing SQL injection: {str(e)}")
        
        self.results['info']['forms_tested'] += len(self.forms)
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        logger.info("Testing for XSS vulnerabilities")
        
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'].lower() in ['text', 'search', '']:
                    for payload in XSS_PAYLOADS:
                        try:
                            data = {input_field['name']: payload}
                            
                            if form['method'] == 'post':
                                response = self.session.post(form['action'], data=data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=data, timeout=10)
                            
                            # Check if the payload is reflected in the response
                            if payload in response.text:
                                self.results['xss'].append({
                                    'url': form['action'],
                                    'method': form['method'],
                                    'field': input_field['name'],
                                    'payload': payload
                                })
                                    
                        except Exception as e:
                            logger.error(f"Error testing XSS: {str(e)}")
    
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        logger.info("Testing for open redirect vulnerabilities")
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'returnTo', 'goto', 'redir', 'destination']
        
        for url in self.visited_urls:
            parsed_url = urlparse(url)
            query_params = parsed_url.query.split('&')
            
            for param in query_params:
                if '=' in param:
                    param_name = param.split('=')[0]
                    
                    if param_name.lower() in redirect_params:
                        for payload in OPEN_REDIRECT_PAYLOADS:
                            try:
                                test_url = url.replace(param, f"{param_name}={payload}")
                                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                                
                                if response.status_code in [301, 302, 303, 307, 308]:
                                    location = response.headers.get('Location', '')
                                    if 'evil.com' in location or any(p.replace('evil.com', '') in location for p in OPEN_REDIRECT_PAYLOADS):
                                        self.results['open_redirect'].append({
                                            'url': url,
                                            'parameter': param_name,
                                            'payload': payload,
                                            'redirect_url': location
                                        })
                                        
                            except Exception as e:
                                logger.error(f"Error testing open redirect: {str(e)}")
    
    def run_scan(self):
        """Run all vulnerability tests"""
        start_time = time.time()
        
        # Crawl the website
        self.crawl()
        
        # Run vulnerability tests
        self.test_sql_injection()
        self.test_xss()
        self.test_open_redirect()
        
        # Record scan completion time
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.results['info']['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.results['info']['scan_duration'] = f"{scan_duration:.2f} seconds"
        
        return self.results
    
    def generate_pdf_report(self, filename):
        """Generate a PDF report of the scan results"""
        c = canvas.Canvas(filename, pagesize=letter)
        width, height = letter
        
        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Web Application Vulnerability Scan Report")
        
        # Scan information
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 80, "Scan Information:")
        c.setFont("Helvetica", 10)
        c.drawString(70, height - 100, f"Target URL: {self.base_url}")
        c.drawString(70, height - 115, f"Scan Start Time: {self.results['info']['start_time']}")
        c.drawString(70, height - 130, f"Scan End Time: {self.results['info']['end_time']}")
        c.drawString(70, height - 145, f"Scan Duration: {self.results['info']['scan_duration']}")
        c.drawString(70, height - 160, f"URLs Scanned: {self.results['info']['scanned_urls']}")
        c.drawString(70, height - 175, f"Forms Tested: {self.results['info']['forms_tested']}")
        
        # Summary of findings
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 205, "Summary of Findings:")
        c.setFont("Helvetica", 10)
        
        y_position = height - 225
        
        # SQL Injection
        c.drawString(70, y_position, f"SQL Injection Vulnerabilities: {len(self.results['sql_injection'])}")
        y_position -= 15
        
        # XSS
        c.drawString(70, y_position, f"Cross-Site Scripting (XSS) Vulnerabilities: {len(self.results['xss'])}")
        y_position -= 15
        
        # Open Redirect
        c.drawString(70, y_position, f"Open Redirect Vulnerabilities: {len(self.results['open_redirect'])}")
        y_position -= 15
        
        # Missing Headers
        c.drawString(70, y_position, f"Missing Security Headers: {len(self.results['missing_headers'])}")
        y_position -= 30
        
        # Detailed findings
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_position, "Detailed Findings:")
        y_position -= 20
        
        # SQL Injection details
        if self.results['sql_injection']:
            c.setFont("Helvetica-Bold", 11)
            c.drawString(50, y_position, "SQL Injection Vulnerabilities:")
            y_position -= 15
            
            c.setFont("Helvetica", 9)
            for i, vuln in enumerate(self.results['sql_injection'], 1):
                if y_position < 100:
                    c.showPage()
                    y_position = height - 50
                    c.setFont("Helvetica", 9)
                
                c.drawString(70, y_position, f"{i}. URL: {vuln['url']}")
                y_position -= 12
                c.drawString(90, y_position, f"Method: {vuln['method'].upper()}")
                y_position -= 12
                c.drawString(90, y_position, f"Field: {vuln['field']}")
                y_position -= 12
                c.drawString(90, y_position, f"Payload: {vuln['payload']}")
                y_position -= 12
                c.drawString(90, y_position, f"Error: {vuln['error']}")
                y_position -= 20
        
        # XSS details
        if self.results['xss']:
            c.setFont("Helvetica-Bold", 11)
            c.drawString(50, y_position, "Cross-Site Scripting (XSS) Vulnerabilities:")
            y_position -= 15
            
            c.setFont("Helvetica", 9)
            for i, vuln in enumerate(self.results['xss'], 1):
                if y_position < 100:
                    c.showPage()
                    y_position = height - 50
                    c.setFont("Helvetica", 9)
                
                c.drawString(70, y_position, f"{i}. URL: {vuln['url']}")
                y_position -= 12
                c.drawString(90, y_position, f"Method: {vuln['method'].upper()}")
                y_position -= 12
                c.drawString(90, y_position, f"Field: {vuln['field']}")
                y_position -= 12
                c.drawString(90, y_position, f"Payload: {vuln['payload']}")
                y_position -= 20
        
        # Open Redirect details
        if self.results['open_redirect']:
            c.setFont("Helvetica-Bold", 11)
            c.drawString(50, y_position, "Open Redirect Vulnerabilities:")
            y_position -= 15
            
            c.setFont("Helvetica", 9)
            for i, vuln in enumerate(self.results['open_redirect'], 1):
                if y_position < 100:
                    c.showPage()
                    y_position = height - 50
                    c.setFont("Helvetica", 9)
                
                c.drawString(70, y_position, f"{i}. URL: {vuln['url']}")
                y_position -= 12
                c.drawString(90, y_position, f"Parameter: {vuln['parameter']}")
                y_position -= 12
                c.drawString(90, y_position, f"Payload: {vuln['payload']}")
                y_position -= 12
                c.drawString(90, y_position, f"Redirect URL: {vuln['redirect_url']}")
                y_position -= 20
        
        # Missing Headers details
        if self.results['missing_headers']:
            c.setFont("Helvetica-Bold", 11)
            c.drawString(50, y_position, "Missing Security Headers:")
            y_position -= 15
            
            c.setFont("Helvetica", 9)
            for i, (header, description) in enumerate(self.results['missing_headers'].items(), 1):
                if y_position < 100:
                    c.showPage()
                    y_position = height - 50
                    c.setFont("Helvetica", 9)
                
                c.drawString(70, y_position, f"{i}. {header}: {description}")
                y_position -= 15
        
        # Recommendations
        if y_position < 150:
            c.showPage()
            y_position = height - 50
        
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y_position, "Recommendations:")
        y_position -= 20
        
        c.setFont("Helvetica", 9)
        recommendations = [
            "Implement input validation and sanitization for all user inputs",
            "Use parameterized queries or prepared statements for database operations",
            "Implement Content Security Policy (CSP) to prevent XSS attacks",
            "Validate all redirect URLs against a whitelist of allowed domains",
            "Implement all recommended security headers",
            "Regularly update and patch all software components",
            "Implement HTTPS across the entire website",
            "Consider implementing a Web Application Firewall (WAF)"
        ]
        
        for rec in recommendations:
            if y_position < 100:
                c.showPage()
                y_position = height - 50
                c.setFont("Helvetica", 9)
            
            c.drawString(70, y_position, f"• {rec}")
            y_position -= 15
        
        c.save()
        return filename

@app.route('/', methods=['GET', 'POST'])
def index():
    form = ScanForm()
    if form.validate_on_submit():
        url = form.url.data
        return scan_website(url)
    return render_template('index.html', form=form)

@app.route('/scan', methods=['POST'])
def scan_website():
    try:
        data = request.get_json() if request.is_json else request.form
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Create scanner instance and run scan
        scanner = VulnerabilityScanner(url)
        results = scanner.run_scan()
        
        # Add target URL to results info
        results['info']['target_url'] = url
        
        # Generate PDF report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"scan_report_{timestamp}.pdf"
        report_path = os.path.join(app.root_path, 'static', 'reports', report_filename)
        
        # Ensure reports directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        scanner.generate_pdf_report(report_path)
        
        # Add report URL to results
        results['info']['report_url'] = f'/static/reports/{report_filename}'
        
        # Store results in session for display
        session_id = os.urandom(16).hex()
        session[f'SCAN_RESULTS_{session_id}'] = results
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'report_url': f'/static/reports/{report_filename}'
        })
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/results/<session_id>')
def view_results(session_id):
    results = session.get(f'SCAN_RESULTS_{session_id}')
    if not results:
        return render_template('error.html', message="Results not found or expired")
    
    return render_template('results.html', results=results)

@app.route('/download_report/<path:filename>')
def download_report(filename):
    reports_dir = os.path.join(app.root_path, 'static', 'reports')
    return send_file(os.path.join(reports_dir, filename), as_attachment=True)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', message="Server error occurred"), 500

if __name__ == '__main__':
    # Ensure reports directory exists
    os.makedirs(os.path.join(app.root_path, 'static', 'reports'), exist_ok=True)
    app.run(debug=True)
