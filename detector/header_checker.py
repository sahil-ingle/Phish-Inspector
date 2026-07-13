# detector/header_checker.py

import re


def check_headers(email_data):
    """
    Analyze email headers.

    Returns:
    {
        "module": "Header Checker",
        "score": int,
        "passed": int,
        "failed": int,
        "skipped": int,
        "checks": [...]
    }
    """

    score = 0
    checks = []

    headers = email_data.get("headers", {})
    sender = email_data.get("sender", "")
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")
    message_id = email_data.get("message_id", "")
    received = email_data.get("received", [])
    auth = email_data.get("authentication_results", "").lower()

    def add_check(name, status, severity, details, risk=0):
        nonlocal score

        if status == "FAIL":
            score += risk

        checks.append({
            "name": name,
            "status": status,
            "severity": severity,
            "details": details
        })

    # -------------------------------------------------
    # Reply-To
    # -------------------------------------------------

    if not reply_to:
        add_check(
            "Reply-To",
            "SKIPPED",
            "Info",
            "Reply-To header not present."
        )

    elif reply_to == sender:
        add_check(
            "Reply-To",
            "PASS",
            "Info",
            "Reply-To matches sender."
        )

    else:
        add_check(
            "Reply-To",
            "FAIL",
            "Medium",
            f"Reply-To ({reply_to}) differs from From ({sender}).",
            20
        )

    # -------------------------------------------------
    # Return-Path
    # -------------------------------------------------

    if return_path:
        add_check(
            "Return-Path",
            "PASS",
            "Info",
            "Return-Path header present."
        )
    else:
        add_check(
            "Return-Path",
            "FAIL",
            "Low",
            "Return-Path header missing.",
            5
        )

    # -------------------------------------------------
    # Message-ID
    # -------------------------------------------------

    if not message_id:
        add_check(
            "Message-ID",
            "FAIL",
            "Low",
            "Message-ID header missing.",
            10
        )

    elif re.match(r"<.+@.+>", message_id):
        add_check(
            "Message-ID",
            "PASS",
            "Info",
            "Message-ID format looks valid."
        )

    else:
        add_check(
            "Message-ID",
            "FAIL",
            "Medium",
            "Malformed Message-ID.",
            15
        )

    # -------------------------------------------------
    # Received Headers
    # -------------------------------------------------

    if received:
        add_check(
            "Received Headers",
            "PASS",
            "Info",
            f"{len(received)} Received header(s) found."
        )

    else:
        add_check(
            "Received Headers",
            "FAIL",
            "High",
            "No Received headers found.",
            25
        )

    # -------------------------------------------------
    # SPF
    # -------------------------------------------------

    if not auth:
        add_check(
            "SPF",
            "SKIPPED",
            "Info",
            "Authentication-Results header missing."
        )

    elif "spf=pass" in auth:
        add_check(
            "SPF",
            "PASS",
            "Info",
            "SPF authentication passed."
        )

    elif "spf=fail" in auth:
        add_check(
            "SPF",
            "FAIL",
            "High",
            "SPF authentication failed.",
            30
        )

    else:
        add_check(
            "SPF",
            "SKIPPED",
            "Info",
            "SPF result not found."
        )

    # -------------------------------------------------
    # DKIM
    # -------------------------------------------------

    if not auth:
        add_check(
            "DKIM",
            "SKIPPED",
            "Info",
            "Authentication-Results header missing."
        )

    elif "dkim=pass" in auth:
        add_check(
            "DKIM",
            "PASS",
            "Info",
            "DKIM authentication passed."
        )

    elif "dkim=fail" in auth:
        add_check(
            "DKIM",
            "FAIL",
            "High",
            "DKIM authentication failed.",
            30
        )

    else:
        add_check(
            "DKIM",
            "SKIPPED",
            "Info",
            "DKIM result not found."
        )

    # -------------------------------------------------
    # DMARC
    # -------------------------------------------------

    if not auth:
        add_check(
            "DMARC",
            "SKIPPED",
            "Info",
            "Authentication-Results header missing."
        )

    elif "dmarc=pass" in auth:
        add_check(
            "DMARC",
            "PASS",
            "Info",
            "DMARC authentication passed."
        )

    elif "dmarc=fail" in auth:
        add_check(
            "DMARC",
            "FAIL",
            "High",
            "DMARC authentication failed.",
            30
        )

    else:
        add_check(
            "DMARC",
            "SKIPPED",
            "Info",
            "DMARC result not found."
        )

    # -------------------------------------------------
    # Summary
    # -------------------------------------------------

    passed = sum(c["status"] == "PASS" for c in checks)
    failed = sum(c["status"] == "FAIL" for c in checks)
    skipped = sum(c["status"] == "SKIPPED" for c in checks)

    return {
        "module": "Header Checker",
        "score": score,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "checks": checks
    }