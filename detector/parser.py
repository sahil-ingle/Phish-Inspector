# detector/parser.py

import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


def extract_urls(text):
    """Extract URLs from text."""
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"
    return list(set(re.findall(pattern, text)))


def parse_eml(file_path):
    """
    Parse an .eml file and return all important fields.

    Returns:
        dict
    """

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # -----------------------
    # Basic Headers
    # -----------------------
    headers = dict(msg.items())

    # -----------------------
    # Email Fields
    # -----------------------
    sender = msg.get("From", "")
    recipient = msg.get("To", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")
    return_path = msg.get("Return-Path", "")
    message_id = msg.get("Message-ID", "")

    # -----------------------
    # Received Headers
    # -----------------------
    received = msg.get_all("Received", [])

    # -----------------------
    # Authentication
    # -----------------------
    authentication = msg.get("Authentication-Results", "")

    # -----------------------
    # Email Body
    # -----------------------
    plain_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():

            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            try:
                if content_type == "text/plain":
                    plain_body += part.get_content()

                elif content_type == "text/html":
                    html_body += part.get_content()

            except Exception:
                pass

    else:
        if msg.get_content_type() == "text/plain":
            plain_body = msg.get_content()

        elif msg.get_content_type() == "text/html":
            html_body = msg.get_content()

    # -----------------------
    # URLs
    # -----------------------

    raw_urls = extract_urls(plain_body + "\n" + html_body)

    urls = []

    for url in raw_urls:

        # Handle URLs like www.example.com
        if url.startswith("www."):
            url = "http://" + url

        parsed = urlparse(url)

        urls.append({
            "url": url,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
        })

    # -----------------------
    # Attachments
    # -----------------------

    attachments = []

    for part in msg.iter_attachments():

        attachments.append({
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size": len(part.get_payload(decode=True) or b"")
        })

    # -----------------------
    # Return Dictionary
    # -----------------------

    return {
        "headers": headers,
        "sender": sender,
        "recipient": recipient,
        "reply_to": reply_to,
        "subject": subject,
        "date": date,
        "return_path": return_path,
        "message_id": message_id,
        "received": received,
        "authentication_results": authentication,
        "plain_body": plain_body,
        "html_body": html_body,
        "urls": urls,
        "attachments": attachments,
    }


def print_email(parsed_email):
    """Pretty-print the parsed email."""

    print("=" * 70)

    for key, value in parsed_email.items():

        print(f"\n{key.upper()}")
        print("-" * 70)

        if isinstance(value, list):

            if not value:
                print("None")

            else:
                for item in value:
                    print(item)

        elif isinstance(value, dict):

            for k, v in value.items():
                print(f"{k}: {v}")

        else:
            print(value)

    print("=" * 70)