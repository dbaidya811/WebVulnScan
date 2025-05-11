# WebVulnScan

A Python-based web application vulnerability scanner with a user-friendly interface for identifying common security vulnerabilities in web applications.

## Features

- **Simple HTML Frontend**: Easy-to-use interface for entering website URLs and configuring scan options
- **Vulnerability Detection**:
  - SQL Injection testing
  - Cross-Site Scripting (XSS) detection
  - Open Redirect vulnerability scanning
  - Security header analysis
- **Crawling Capabilities**: Automatically discovers and scans internal links using BeautifulSoup
- **Detailed Reporting**: Generates comprehensive HTML reports and downloadable PDF documentation
- **Modern UI**: Clean, responsive design with clear vulnerability categorization

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

1. Run the Flask application:

```
python app.py
```

2. Open your web browser and navigate to `http://127.0.0.1:5000`

3. Enter the URL of the website you want to scan
4. Configure scan options if needed
5. Click "Scan Website" to start the vulnerability assessment
6. View the detailed results and download the PDF report if desired

## Technical Details

- **Backend**: Flask web framework
- **HTTP Requests**: Uses requests/httpx libraries for sending HTTP requests
- **HTML Parsing**: BeautifulSoup and lxml for crawling and parsing web pages
- **PDF Generation**: ReportLab for creating downloadable PDF reports
- **Optional Selenium Support**: For handling JavaScript-rendered pages

## Security Notes

- This tool is intended for security professionals and developers to test their own applications
- Always obtain proper authorization before scanning any website
- Some vulnerability tests may trigger security mechanisms or impact website functionality
- Use responsibly and ethically

## Potential Improvements

- **Additional Vulnerability Tests**:
  - CSRF (Cross-Site Request Forgery) detection
  - SSRF (Server-Side Request Forgery) testing
  - JWT token analysis
  - API security scanning
  - File upload vulnerability testing
  - Directory traversal detection
  - XML External Entity (XXE) testing
  - Server misconfigurations detection

- **Enhanced Features**:
  - Authentication support for testing protected areas
  - Custom payload configuration
  - Scan scheduling and history
  - Integration with CI/CD pipelines
  - Export results in multiple formats (JSON, CSV)
  - Rate limiting and stealth mode options
  - Vulnerability severity scoring

## License

MIT License
