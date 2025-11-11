 # PenPy : Advanced Penetration Testing Tool

![Security Shield](https://img.icons8.com/color/96/000000/security-checked--v2.png)  
*A comprehensive security auditing tool with AI-powered analysis*

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Technical Specifications](#technical-specifications)
- [Security Considerations](#security-considerations)
- [Sample Reports](#sample-reports)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)
- [License](#license)

## Features 
- **Multi-Vector Vulnerability Scanning**
  - Directory Traversal
  - Command Injection
  - Insecure Headers
  - TLS/SSL Misconfigurations
  - API Endpoint Detection (REST/GraphQL)
  
- **Smart Crawling Engine**
  - Depth-controlled website crawling
  - Form detection & CSRF awareness
  - Domain boundary enforcement

- **AI-Powered Analysis** (Opt-in)
  - GPT-3.5 Turbo false positive reduction
  - Context-aware response evaluation

- **Enterprise-Grade Security**
  - Rate limiting (5 req/sec)
  - Thread-safe operations
  - Payload sanitization
  - Certificate validation

## Installation 

### Requirements
- Python 3.8+
- OpenSSL 1.1.1+

```bash
# Clone repository
git clone https://github.com/RicheByte/penPy
cd penPy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/MacOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration ⚙️

1. **API Keys**
```bash
# Set OpenAI API key
export OPENAI_API_KEY='your-api-key-here'  # Linux/MacOS
setx OPENAI_API_KEY "your-api-key-here"    # Windows
```

1. **Payload Directory**
```
secuscan-pro/
├── payloads/
│   ├── directory_traversal.json
│   ├── command_injection.json
│   └── xss.json
```

Sample payload file (`payloads/directory_traversal.json`):
```json
{
    "payloads": [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "%252e%252e%252fetc%252fpasswd"
    ]
}
```

## Usage 

### Basic Scan
```bash
python Pen.py --target https://example.com --threads 8
```

### Full Audit with AI Analysis
```bash
python pen.py --target https://example.com \
                   --crawl \
                   --auth admin password123 \
                   --report-format html \
                   --allow-ai-analysis \
                   --threads 10
```

### Command Line Options
| Option | Description |
|--------|-------------|
| `--target` | Target URL (required) |
| `--crawl` | Enable website crawling (max depth=2) |
| `--auth` | Authentication credentials (user pass) |
| `--report-format` | Output format: json/html (default: json) |
| `--threads` | Concurrent workers (default: 5) |
| `--allow-ai-analysis` | Enable OpenAI integration |

## Technical Specifications 

| Category | Details |
|----------|---------|
| **Supported Protocols** | HTTP/HTTPS/WebSocket |
| **Security Standards** | OWASP Top 10 2023 |
| **Performance** | 100 endpoints/min (typical) |
| **Data Handling** | No persistent storage |
| **Network Requirements** | Outbound HTTPS access |

## Security Considerations 

1. **Legal Compliance**
   - Obtain proper authorization before scanning
   - Respect robots.txt directives
   - Adhere to regional cybersecurity laws

2. **Risk Mitigation**
   - Avoid production environments
   - Use `--threads 1` for fragile systems
   - Monitor network impact during scans

3. **Data Privacy**
   - AI analysis disabled by default
   - Response data truncated before API submission
   - No sensitive data storage

## Sample Reports 

**JSON Report Excerpt**
```json
{
    "timestamp": 1689612602,
    "vulnerabilities": [
        {
            "type": "TLS/SSL Configuration",
            "details": "https://example.com:443: Certificate expires 2023-12-31",
            "severity": "medium"
        }
    ]
}
```

**HTML Report Features**
- Interactive vulnerability filters
- TLS certificate timeline
- Response snippet viewer
- Exportable findings list

## Troubleshooting 

| Issue | Solution |
|-------|----------|
| `Missing Dependencies` | Run `pip install -r requirements.txt --force-reinstall` |
| `SSL Verification Failed` | Update root certificates |
| `API Timeouts` | Reduce thread count with `--threads 3` |
| `Encoding Errors` | Set `export PYTHONIOENCODING=utf-8` |

## Credits 

- **OWASP Foundation** - Vulnerability references
- **OpenAI** - GPT-3.5 Turbo integration
- **Cryptography** - X.509 certificate handling



**Disclaimer**: This tool should only be used on systems with explicit authorization. The developers assume no liability for unauthorized or malicious use. Always conduct security testing in controlled environments.
