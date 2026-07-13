# Phish Inspector

**Phish Inspector** is a Python-based phishing email analysis tool that helps identify potentially malicious emails through header inspection and URL analysis. The project is designed to provide an easy-to-understand risk assessment by analyzing common phishing indicators.

> 🚧 **Work in Progress**
>
> This project is currently under active development. Features, output formats, and detection logic may change as new modules are added.

---

## Current Features

* 📧 Parse `.eml` email files
* 🔍 Header analysis

  * Reply-To mismatch
  * Return-Path validation
  * Message-ID validation
  * Received header checks
  * SPF validation
  * DKIM validation
  * DMARC validation
* 🌐 Offline URL analysis

  * HTTPS detection
  * IP address detection
  * URL shortener detection
  * Punycode detection
  * Suspicious TLD detection
  * Long URL detection
  * Excessive subdomain detection
  * `@` symbol detection
* 📊 Risk scoring
* 📄 Console-based analysis report

---

## Planned Features

* VirusTotal integration
* URLScan.io integration
* Google Safe Browsing support
* Attachment analysis
* QR code detection
* HTML content analysis
* IOC extraction
* PDF and HTML report generation
* Threat intelligence integration
* Machine learning-based phishing detection
* Web interface

---

## Project Structure

```text
Phish Inspector/
│
├── detector/
│   ├── parser.py
│   ├── header_checker.py
│   ├── url_checker.py
│   └── report.py
│
├── sample_emails/
│   └── sample1.eml
│
└── main.py
```

---

## Usage

Run the project using:

```bash
python main.py
```

You will be prompted to choose whether to perform offline URL analysis.

---

## Requirements

* Python 3.12+
* No external dependencies (currently uses only the Python Standard Library)

---

## Status

**Current Version:** Early Development

Modules completed:

* ✅ Email Parser
* ✅ Header Checker
* ✅ Offline URL Checker

Modules in progress:

* 🚧 Report Improvements
* 🚧 Online URL Reputation Checks
* 🚧 Attachment Analysis

---

## Disclaimer

This tool is intended for educational purposes and security research. It should be used as a supplementary analysis tool and not as the sole source for determining whether an email is malicious.
