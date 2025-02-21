import email
import re
from email import policy
from email.parser import BytesParser
import requests
from bs4 import BeautifulSoup
import mimetypes
import joblib
from typing import List, Optional

class BasicEmailParser:
    def __init__(self, file_path: str):
        self.file_path = file_path.strip('"')
        self.msg = None
        self.result_text = ""

    def parse_email(self):
        try:
            with open(self.file_path, 'rb') as file:
                self.msg = BytesParser(policy=policy.default).parse(file)
            self._print_headers()
            self._trace_route()
            self._analyze_body()
            self._check_spf_dkim_dmarc()
            self._analyze_attachments()
            self._export_report()
        except (FileNotFoundError, OSError) as e:
            print(f"Error reading file '{self.file_path}': {e}")

    def _print_headers(self):
        headers = ["From", "To", "Subject", "Date", "Message-ID"]
        self.result_text += "\n=== EMAIL HEADER ANALYSIS ===\n"
        for header in headers:
            self.result_text += f"{header}: {self.msg.get(header, 'N/A')}\n"

    def _trace_route(self):
        received_headers = self.msg.get_all('Received', [])
        self.result_text += "\n--- Received Headers (Route Trace) ---\n"
        for i, header in enumerate(received_headers, 1):
            self.result_text += f"{i}. {header}\n"
        sender_ip = self._extract_sender_ip(received_headers)
        if sender_ip:
            self.result_text += f"\n--- Extracted Sender IP ---\nSender IP: {sender_ip}\nGeolocation (Approximate): {self._geolocate_ip(sender_ip)}\n"

    def _extract_sender_ip(self, received_headers: List[str]) -> Optional[str]:
        for header in received_headers:
            match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
            if match:
                return match.group(0)
        return None

    def _geolocate_ip(self, ip_address: str) -> str:
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            if response.status_code == 200:
                data = response.json()
                return f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}"
        except requests.RequestException:
            return "Geolocation lookup failed"
        return "Unknown"

    def _analyze_body(self):
        content = self._get_email_content(self.msg)
        if content:
            self._analyze_links(content)
            self._detect_phishing(content)

    def _get_email_content(self, msg) -> str:
        content_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    try:
                        content = part.get_payload(decode=True)
                        if content:
                            content_parts.append(content.decode(part.get_content_charset() or 'utf-8', errors='ignore'))
                    except (TypeError, UnicodeDecodeError):
                        continue
        else:
            try:
                content = msg.get_payload(decode=True)
                if content:
                    return content.decode(msg.get_content_charset() or 'utf-8', errors='ignore')
            except (TypeError, UnicodeDecodeError):
                return ""
        return "\n".join(content_parts)

    def _analyze_links(self, content: str):
        soup = BeautifulSoup(content, 'html.parser')
        links = soup.find_all('a', href=True)
        self.result_text += "\n--- Extracted Links ---\n"
        if links:
            suspicious_found = False
            for i, link in enumerate(links, 1):
                self.result_text += f"{i}. {link.text.strip()} -> {link['href']}\n"
                if any(keyword in link['href'] for keyword in ['login', 'verify', 'account', 'reset', 'bank']):
                    self.result_text += f"   [!] Suspicious Link Detected: {link['href']}\n"
                    suspicious_found = True
            if not suspicious_found:
                self.result_text += "No suspicious links found.\n"
        else:
            self.result_text += "No links found.\n"

    def _check_spf_dkim_dmarc(self):
        self.result_text += "\n--- Email Authentication Checks ---\n"
        spf_result = self.msg.get("Received-SPF", "Not Available")
        dkim_result = self.msg.get("DKIM-Signature", "Not Available")
        dmarc_result = self.msg.get("Authentication-Results", "Not Available")

        self.result_text += f"SPF Check: {spf_result}\n"
        self.result_text += f"DKIM Check: {dkim_result}\n"
        self.result_text += f"DMARC Check: {dmarc_result}\n"

    def _analyze_attachments(self):
        self.result_text += "\n=== ATTACHMENT ANALYSIS ===\n"
        for part in self.msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    self.result_text += f"Attachment Found: {filename}\n"
                    content_type, _ = mimetypes.guess_type(filename)
                    if content_type and "application" in content_type:
                        self.result_text += f"   [!] Potential Dangerous File: {filename}\n"

    def _detect_phishing(self, content: str):
        # Simple heuristic-based check for phishing terms
        self.result_text += "\n--- Phishing Detection ---\n"
        phishing_terms = ['login', 'password', 'credit card', 'account', 'verify']
        if any(term in content.lower() for term in phishing_terms):
            self.result_text += "[!] Phishing indicators found in email content.\n"
        else:
            self.result_text += "No phishing indicators found.\n"

    def _export_report(self):
        report_filename = f"email_forensic_report.txt"
        with open(report_filename, 'w') as report_file:
            report_file.write(self.result_text)
        print(f"\nForensic analysis report saved as '{report_filename}'")

# Main function
def main():
    email_files = []
    print("Enter email file paths (type 'done' when finished):")
    while True:
        file_path = input("File path: ")
        if file_path.lower() == 'done':
            break
        email_files.append(file_path.strip('"'))

    if not email_files:
        print("No files provided. Exiting.")
        return

    for file_path in email_files:
        parser = BasicEmailParser(file_path)
        parser.parse_email()
        print(parser.result_text)

if __name__ == "__main__":
    main()
