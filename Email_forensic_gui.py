import email
import re
from email import policy
from email.parser import BytesParser
import requests
from bs4 import BeautifulSoup
import mimetypes
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from typing import List, Optional


class EmailForensicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Forensic Tool")
        self.root.geometry("800x550")
        self.root.configure(bg="#f4f4f4")  # Light gray background
        
        # Title Label
        title_label = ttk.Label(root, text="Email Forensic Tool", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # File Selection Frame
        frame_top = ttk.Frame(root, padding=(10, 5))
        frame_top.pack(pady=5, fill="x")
        
        self.label = ttk.Label(frame_top, text="Select an Email File (.eml):", font=("Arial", 12))
        self.label.pack(side="left", padx=10)
        
        self.file_button = ttk.Button(frame_top, text="Browse", command=self.load_email_file)
        self.file_button.pack(side="left", padx=10)
        
        # Analysis Buttons Frame
        frame_buttons = ttk.Frame(root, padding=(10, 5))
        frame_buttons.pack(pady=5, fill="x")
        
        self.analyze_button = ttk.Button(frame_buttons, text="Analyze Email", command=self.analyze_email, state=tk.DISABLED)
        self.analyze_button.pack(side="left", padx=10)
        
        self.save_button = ttk.Button(frame_buttons, text="Save Report", command=self.save_report, state=tk.DISABLED)
        self.save_button.pack(side="left", padx=10)
        
        # Result Text Area
        frame_result = ttk.Frame(root, padding=(10, 5))
        frame_result.pack(pady=10, fill="both", expand=True)
        
        ttk.Label(frame_result, text="Analysis Results:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
        
        self.result_text = scrolledtext.ScrolledText(frame_result, wrap=tk.WORD, width=95, height=20, font=("Courier", 10))
        self.result_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        # Internal Data
        self.file_path = None
        self.result_text_data = ""

    def load_email_file(self):
        """Opens a file dialog to select an email file."""
        self.file_path = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml")])
        if self.file_path:
            self.analyze_button.config(state=tk.NORMAL)

    def analyze_email(self):
        """Analyzes the selected email file and displays the results."""
        if self.file_path:
            parser = BasicEmailParser(self.file_path)
            parser.parse_email()
            self.result_text_data = parser.result_text
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, self.result_text_data)
            self.save_button.config(state=tk.NORMAL)

    def save_report(self):
        """Saves the forensic report to a text file."""
        if self.result_text_data:
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if save_path:
                with open(save_path, "w") as file:
                    file.write(self.result_text_data)
                messagebox.showinfo("Success", "Report saved successfully!")


class BasicEmailParser:
    """Class to perform email forensic analysis."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path.strip('"')
        self.msg = None
        self.result_text = ""

    def parse_email(self):
        """Parses the email and performs forensic analysis."""
        try:
            with open(self.file_path, 'rb') as file:
                self.msg = BytesParser(policy=policy.default).parse(file)
            self._print_headers()
            self._trace_route()
            self._analyze_body()
            self._check_spf_dkim_dmarc()
            self._analyze_attachments()
        except (FileNotFoundError, OSError) as e:
            self.result_text += f"Error reading file: {e}\n"

    def _print_headers(self):
        """Extracts and displays email headers."""
        headers = ["From", "To", "Subject", "Date", "Message-ID"]
        self.result_text += "\n=== EMAIL HEADER ANALYSIS ===\n"
        for header in headers:
            self.result_text += f"{header}: {self.msg.get(header, 'N/A')}\n"

    def _trace_route(self):
        """Analyzes the email route by extracting received headers."""
        received_headers = self.msg.get_all('Received', [])
        self.result_text += "\n--- Received Headers (Route Trace) ---\n"
        for i, header in enumerate(received_headers, 1):
            self.result_text += f"{i}. {header}\n"
        sender_ip = self._extract_sender_ip(received_headers)
        if sender_ip:
            self.result_text += f"\nSender IP: {sender_ip}\nGeolocation: {self._geolocate_ip(sender_ip)}\n"

    def _extract_sender_ip(self, received_headers: List[str]) -> Optional[str]:
        """Extracts sender IP from headers."""
        for header in received_headers:
            match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
            if match:
                return match.group(0)
        return None

    def _geolocate_ip(self, ip_address: str) -> str:
        return "Feature Disabled (Offline Mode)"

    def _analyze_body(self):
        """Extracts and analyzes email content."""
        content = self._get_email_content(self.msg)
        if content:
            self._analyze_links(content)

    def _get_email_content(self, msg) -> str:
        """Extracts plain text and HTML content from the email body."""
        content_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    try:
                        content_parts.append(part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore'))
                    except (TypeError, UnicodeDecodeError):
                        continue
        else:
            try:
                return msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
            except (TypeError, UnicodeDecodeError):
                return ""
        return "\n".join(content_parts)

    def _analyze_links(self, content: str):
        """Extracts and scans links for phishing attempts."""
        soup = BeautifulSoup(content, 'html.parser')
        links = soup.find_all('a', href=True)
        self.result_text += "\n--- Extracted Links ---\n"
        for i, link in enumerate(links, 1):
            self.result_text += f"{i}. {link.text.strip()} -> {link['href']}\n"

    def _check_spf_dkim_dmarc(self):
        """Checks SPF, DKIM, and DMARC authentication."""
        self.result_text += "\n--- Email Authentication Checks ---\n"
        self.result_text += f"SPF Check: {self.msg.get('Received-SPF', 'Not Available')}\n"
        self.result_text += f"DKIM Check: {self.msg.get('DKIM-Signature', 'Not Available')}\n"
        self.result_text += f"DMARC Check: {self.msg.get('Authentication-Results', 'Not Available')}\n"

    def _analyze_attachments(self):
        """Scans email attachments for potential threats."""
        self.result_text += "\n=== ATTACHMENT ANALYSIS ===\n"
        for part in self.msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    self.result_text += f"Attachment Found: {filename}\n"


if __name__ == "__main__":
    root = tk.Tk()
    app = EmailForensicGUI(root)
    root.mainloop()
