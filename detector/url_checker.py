# detector/url_checker.py

import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "gq",
    "tk", "ml", "cf", "work", "support", "buzz"
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at"
}


def check_urls(email_data):

    urls = email_data.get("urls", [])

    score = 0
    checks = []

    def add_check(url, name, status, severity, details, risk=0):
        nonlocal score

        if status == "FAIL":
            score += risk

        checks.append({
            "url": url,
            "name": name,
            "status": status,
            "severity": severity,
            "details": details
        })

    if not urls:
        return {
            "module": "URL Checker",
            "score": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 1,
            "checks": [{
                "url": "",
                "name": "URLs",
                "status": "SKIPPED",
                "severity": "Info",
                "details": "No URLs found."
            }]
        }

    for url_data in urls:

        url = url_data["url"]
        host = url_data["hostname"]
        scheme = url_data["scheme"]

        parsed = urlparse(url)   # optional

        # -----------------------
        # HTTPS
        # -----------------------

        if parsed.scheme == "https":
            add_check(
                url,
                "HTTPS",
                "PASS",
                "Info",
                "Using HTTPS."
            )

        else:
            add_check(
                url,
                "HTTPS",
                "FAIL",
                "Medium",
                "Uses HTTP.",
                10
            )

        # -----------------------
        # IP Address
        # -----------------------

        try:
            ipaddress.ip_address(host)

            add_check(
                url,
                "IP Address URL",
                "FAIL",
                "High",
                "URL uses an IP address.",
                25
            )

        except Exception:

            add_check(
                url,
                "IP Address URL",
                "PASS",
                "Info",
                "Domain name used."
            )

        # -----------------------
        # URL Shortener
        # -----------------------

        if host.lower() in URL_SHORTENERS:

            add_check(
                url,
                "Shortened URL",
                "FAIL",
                "Medium",
                "Known URL shortening service.",
                15
            )

        else:

            add_check(
                url,
                "Shortened URL",
                "PASS",
                "Info",
                "Not shortened."
            )

        # -----------------------
        # Punycode
        # -----------------------

        if "xn--" in host.lower():

            add_check(
                url,
                "Punycode",
                "FAIL",
                "High",
                "Internationalized domain detected.",
                25
            )

        else:

            add_check(
                url,
                "Punycode",
                "PASS",
                "Info",
                "Normal domain."
            )

        # -----------------------
        # Suspicious TLD
        # -----------------------

        tld = host.split(".")[-1].lower()

        if tld in SUSPICIOUS_TLDS:

            add_check(
                url,
                "Suspicious TLD",
                "FAIL",
                "Medium",
                f".{tld} is commonly abused.",
                15
            )

        else:

            add_check(
                url,
                "Suspicious TLD",
                "PASS",
                "Info",
                f".{tld} appears normal."
            )

        # -----------------------
        # URL Length
        # -----------------------

        if len(url) > 150:

            add_check(
                url,
                "Long URL",
                "FAIL",
                "Medium",
                f"Length = {len(url)}",
                10
            )

        else:

            add_check(
                url,
                "Long URL",
                "PASS",
                "Info",
                f"Length = {len(url)}"
            )

        # -----------------------
        # Too Many Subdomains
        # -----------------------

        labels = host.split(".")

        if len(labels) > 4:

            add_check(
                url,
                "Subdomains",
                "FAIL",
                "Medium",
                f"{len(labels)-2} subdomains detected.",
                10
            )

        else:

            add_check(
                url,
                "Subdomains",
                "PASS",
                "Info",
                "Normal number of subdomains."
            )

        # -----------------------
        # '@' Symbol
        # -----------------------

        if "@" in url:

            add_check(
                url,
                "@ Symbol",
                "FAIL",
                "High",
                "@ symbol present in URL.",
                20
            )

        else:

            add_check(
                url,
                "@ Symbol",
                "PASS",
                "Info",
                "No @ symbol."
            )

    passed = sum(c["status"] == "PASS" for c in checks)
    failed = sum(c["status"] == "FAIL" for c in checks)
    skipped = sum(c["status"] == "SKIPPED" for c in checks)

    return {
        "module": "URL Checker",
        "score": score,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "checks": checks
    }