import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import tldextract
import Levenshtein
import requests
from threading import Thread, Lock
import whois
import time
import datetime
import re
import ssl
import logging
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import socket

# Configure logging
logging.basicConfig(
    filename='phishing_detector.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PhishingDetector:
    def __init__(self):
        self.legitimate_domains = set(["example.com", "google.com", "facebook.com"])
        self.blacklisted_urls = set(["phishingsite.com", "malicious.com", "fakebank.com"])
        self.check_count = 0
        self.last_check_time = 0
        self.lock = Lock()
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour cache timeout
        # Adjusted weights for better accuracy
        self.safety_metrics = {
            'domain_age': 0.25,      # Increased weight for domain age
            'ssl_cert': 0.25,        # Increased weight for SSL certificate
            'url_structure': 0.20,    # Increased weight for URL structure
            'blacklist': 0.20,       # Adjusted blacklist weight
            'typosquatting': 0.10    # Reduced weight for typosquatting
        }
        self.flagged_counts = {}

    def calculate_safety_score(self, url):
        scores = {}
        url = url.strip().lower()
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()

        # Enhanced domain age scoring
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                age_years = (datetime.datetime.now().year - creation_date.year)
                # More granular age scoring
                if age_years >= 5:
                    scores['domain_age'] = self.safety_metrics['domain_age']
                elif age_years >= 2:
                    scores['domain_age'] = self.safety_metrics['domain_age'] * 0.7
                else:
                    scores['domain_age'] = self.safety_metrics['domain_age'] * 0.2
            else:
                scores['domain_age'] = 0
        except:
            scores['domain_age'] = 0

        # Enhanced SSL certificate scoring
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                # Check certificate expiry
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if datetime.datetime.now() < not_after:
                    scores['ssl_cert'] = self.safety_metrics['ssl_cert']
                else:
                    scores['ssl_cert'] = 0
        except:
            scores['ssl_cert'] = 0

        # Enhanced URL structure scoring
        suspicious_chars = ['@', '_', '%', '-', '=', '+']
        char_count = sum(1 for char in url if char in suspicious_chars)
        length_penalty = len(url) > 40 and 0.3 or 0  # Lowered threshold, higher penalty
        subdomain_penalty = len(extracted.subdomain.split('.')) > 1 and 0.3 or 0  # More strict
        scores['url_structure'] = self.safety_metrics['url_structure'] * \
            (1 - min((char_count / 2 + length_penalty + subdomain_penalty), 1))

        # Enhanced blacklist scoring
        scores['blacklist'] = 0 if domain in self.blacklisted_urls else self.safety_metrics['blacklist']

        # Enhanced typosquatting detection
        min_distance = float('inf')
        for legit in self.legitimate_domains:
            distance = Levenshtein.distance(domain, legit.lower())
            min_distance = min(min_distance, distance)
        # Lower threshold for more sensitivity
        scores['typosquatting'] = self.safety_metrics['typosquatting'] * \
            (1 if min_distance > 3 else (min_distance / 3))

        return scores

    def validate_url(self, url):
        if not url or not isinstance(url, str):
            return False
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def check_ssl_cert(self, domain):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                return True
        except:
            return False

    def is_phishing(self, url):
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_check_time < 1:  # 1 second delay between checks
            return "Rate limit exceeded"
        self.last_check_time = current_time

        # Check cache
        if url in self.cache:
            cache_time, result = self.cache[url]
            if time.time() - cache_time < self.cache_timeout:
                return result

        if not self.validate_url(url):
            return True

        url = url.strip().lower()
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()

        # Enhanced security checks
        if any(char in domain for char in ['@', '_', '%', '-']):
            return True

        if len(domain) > 50:  # Suspicious if domain is too long
            return True

        if domain in self.blacklisted_urls:
            return True

        if domain in self.legitimate_domains:
            return False

        # Check for typosquatting
        for legit in self.legitimate_domains:
            if Levenshtein.distance(domain, legit.lower()) < 3:
                return True

        # Check for HTTPS and SSL certificate
        if not url.startswith("https://"):
            return True
        if not self.check_ssl_cert(domain):
            return True

        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                if (datetime.datetime.now().year - creation_date.year) < 1:
                    return True
                if creation_date.year > datetime.datetime.now().year:
                    return True
        except Exception as e:
            logging.error(f"WHOIS lookup error for {domain}: {str(e)}")
            return True

        result_is_phishing = False
        # Learning: auto-blacklist after 3 flags
        self.flagged_counts[domain] = self.flagged_counts.get(domain, 0) + 1
        if self.flagged_counts[domain] >= 3:
            self.blacklisted_urls.add(domain)
        # Cache the result
        self.cache[url] = (time.time(), result_is_phishing)
        return result_is_phishing

    def ai_analyse_url(self, url, scores):
        """
        Simulate an AI-based analysis of the URL.
        Returns a dictionary with AI verdict and explanation.
        """
        total_score = sum(scores.values())
        if total_score >= 0.85:
            verdict = "Highly Safe"
            explanation = "AI analysis indicates this URL is highly trustworthy based on multiple safety signals."
        elif total_score >= 0.7:
            verdict = "Likely Safe"
            explanation = "AI analysis suggests this URL is likely safe, but caution is advised."
        elif total_score >= 0.5:
            verdict = "Suspicious"
            explanation = "AI analysis finds suspicious patterns. Proceed with caution."
        else:
            verdict = "Phishing Likely"
            explanation = "AI analysis strongly suspects this URL is a phishing attempt."
        # You can expand this logic with more advanced ML models if available.
        return {
            "verdict": verdict,
            "explanation": explanation,
            "score": total_score
        }

    def get_top_risks(self, scores):
        # Returns the top 2 risk factors (lowest scoring features)
        sorted_scores = sorted(scores.items(), key=lambda x: x[1])
        return [f"{k.replace('_',' ').title()}: {v:.2f}" for k, v in sorted_scores[:2]]

    def suggest_legit_domain(self, url):
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        closest = min(self.legitimate_domains, key=lambda legit: Levenshtein.distance(domain, legit))
        return closest

    def categorize_url(self, url):
        categories = {
            "Banking": ["bank", "paypal", "chase", "wellsfargo"],
            "Social Media": ["facebook", "twitter", "instagram", "linkedin"],
            "Shopping": ["amazon", "ebay", "shop", "flipkart"]
        }
        for cat, keywords in categories.items():
            if any(k in url for k in keywords):
                return cat
        return "Other"

    def check_google_safe_browsing(self, url):
        api_key = "YOUR_API_KEY"  # Replace with your actual API key
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "utds-phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            response = requests.post(endpoint, json=payload, timeout=5)
            result = response.json()
            return bool(result.get("matches"))
        except Exception as e:
            logging.error(f"Google Safe Browsing API error: {str(e)}")
            return False

class PhishingDetectorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("UTDS with Safety Score Analyser")
        self.root.configure(bg="#181c24")  # Dark background
        self.detector = PhishingDetector()
        self.setup_gui()
        self.setup_graph()

    def setup_gui(self):
        # Futuristic header
        header = tk.Label(self.root, text="🛡️ UTDS Safety Score Analyser", 
                          font=("Segoe UI", 22, "bold"), fg="#00ffe7", bg="#181c24", pady=10)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0)

        # Main frame with border and accent
        main_frame = ttk.Frame(self.root, padding="15", style="Main.TFrame")
        main_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=20, pady=10)

        # URL Entry
        ttk.Label(main_frame, text="Enter URL:", style="Accent.TLabel").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(main_frame, width=50, font=("Consolas", 12))
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        # Buttons frame
        button_frame = ttk.Frame(main_frame, style="Main.TFrame")
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self._styled_button(button_frame, "Check URL", self.check_url).pack(side=tk.LEFT, padx=5)
        self._styled_button(button_frame, "Clear History", self.clear_history).pack(side=tk.LEFT, padx=5)

        # Results area with custom Listbox
        self.result_frame = ttk.Frame(main_frame, style="Main.TFrame")
        self.result_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.url_listbox = tk.Listbox(self.result_frame, width=70, height=10, 
                                      bg="#232a34", fg="#00ffe7", font=("Consolas", 11), 
                                      selectbackground="#00ffe7", selectforeground="#232a34", 
                                      highlightthickness=2, highlightcolor="#00ffe7", relief=tk.FLAT)
        scrollbar = ttk.Scrollbar(self.result_frame, orient=tk.VERTICAL, command=self.url_listbox.yview)
        self.url_listbox.configure(yscrollcommand=scrollbar.set)
        self.url_listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.result_frame.rowconfigure(0, weight=1)
        self.result_frame.columnconfigure(0, weight=1)

        # Graph frame
        self.graph_frame = ttk.Frame(main_frame, style="Main.TFrame")
        self.graph_frame.grid(row=3, column=0, columnspan=2, pady=10)
        main_frame.rowconfigure(3, weight=1)

        # Description panel
        self.description_frame = ttk.LabelFrame(main_frame, text="Analysis Details", padding="5", style="Accent.TLabelframe")
        self.description_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.description_text = tk.Text(self.description_frame, height=4, width=60, wrap=tk.WORD,
                                        bg="#232a34", fg="#00ffe7", font=("Segoe UI", 11), relief=tk.FLAT)
        self.description_text.pack(fill=tk.BOTH, expand=True)
        self.description_text.config(state=tk.DISABLED)

        # --- Add AI Report Panel ---
        self.ai_report_frame = ttk.LabelFrame(main_frame, text="AI Analysing Report", padding="5", style="Accent.TLabelframe")
        self.ai_report_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # Add a scrollbar to the AI report text box
        ai_scrollbar = ttk.Scrollbar(self.ai_report_frame, orient=tk.VERTICAL)
        self.ai_report_text = tk.Text(
            self.ai_report_frame, height=8, width=60, wrap=tk.WORD,
            bg="#232a34", fg="#00ffe7", font=("Segoe UI", 11), relief=tk.FLAT,
            yscrollcommand=ai_scrollbar.set
        )
        ai_scrollbar.config(command=self.ai_report_text.yview)
        self.ai_report_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ai_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.ai_report_text.config(state=tk.DISABLED)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, style="Accent.TLabel")
        status_bar.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E))

        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Main.TFrame", background="#181c24")
        style.configure("Accent.TLabel", background="#181c24", foreground="#00ffe7", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TLabelframe", background="#181c24", foreground="#00ffe7", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TLabelframe.Label", background="#181c24", foreground="#00ffe7")
        style.map("TButton",
                  background=[('active', '#00ffe7'), ('!active', '#232a34')],
                  foreground=[('active', '#181c24'), ('!active', '#00ffe7')])

        # Make the main window and frames expandable
        self.root.rowconfigure(1, weight=1)
        self.root.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.columnconfigure(1, weight=1)
        self.result_frame.rowconfigure(0, weight=1)
        self.result_frame.columnconfigure(0, weight=1)
        self.graph_frame.rowconfigure(0, weight=1)
        self.graph_frame.columnconfigure(0, weight=1)
        self.description_frame.rowconfigure(0, weight=1)
        self.description_frame.columnconfigure(0, weight=1)
        self.ai_report_frame.rowconfigure(0, weight=1)
        self.ai_report_frame.columnconfigure(0, weight=1)

    def _styled_button(self, parent, text, command):
        btn = ttk.Button(parent, text=text, command=command, style="Accent.TButton")
        btn.bind("<Enter>", lambda e: btn.configure(style="Accent.TButton"))
        btn.bind("<Leave>", lambda e: btn.configure(style="Accent.TButton"))
        return btn

    def setup_graph(self):
        self.figure = Figure(figsize=(8, 3), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.get_tk_widget().pack()

    def update_graph(self, scores):
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        # Remove domain_age from categories and values
        categories = [k for k in scores.keys() if k != 'domain_age']
        values = [v for k, v in scores.items() if k != 'domain_age']
        positions = np.arange(len(categories))

        # Create bars with custom colors
        colors = ['#3498db', '#9b59b6', '#e74c3c', '#f1c40f']  # One less color
        bars = ax.bar(positions, values, align='center', color=colors)

        # Customize the graph
        ax.set_xticks(positions)
        ax.set_xticklabels([c.replace('_', ' ').title() for c in categories], rotation=45)
        ax.set_ylim(0, 0.3)
        ax.set_title('URL Safety Score Analysis')
        ax.set_ylabel('Score')

        # Add value labels on top of bars
        for idx, bar in enumerate(bars):
            height = bar.get_height()
            label = f'{height:.2f}'
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    label,
                    ha='center', va='bottom')

        self.figure.tight_layout()
        self.canvas.draw()

        # Show domain age or date separate from the graph (in the description panel)
        try:
            url = self.url_entry.get().strip().lower()
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}".lower()
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                domain_age_text = f"Domain Creation Date: {creation_date.strftime('%Y-%m-%d') if hasattr(creation_date, 'strftime') else creation_date}"
            else:
                domain_age_text = "Domain Creation Date: Unknown"
        except Exception:
            domain_age_text = "Domain Creation Date: Unknown"

        # Place the domain age info in the description panel below the graph
        self.description_text.config(state=tk.NORMAL)
        current_text = self.description_text.get(1.0, tk.END)
        if "Domain Creation Date:" in current_text:
            # Remove previous domain age info if present
            lines = current_text.strip().split('\n')
            lines = [line for line in lines if not line.startswith("Domain Creation Date:")]
            current_text = '\n'.join(lines)
        self.description_text.delete(1.0, tk.END)
        self.description_text.insert(tk.END, current_text.strip() + f"\n\n{domain_age_text}\n")
        self.description_text.config(state=tk.DISABLED)

    def update_description(self, url, scores):
        total_score = sum(scores.values())
        percentage = total_score * 100

        # Prepare detailed analysis
        details = []
        if scores['domain_age'] > 0:
            details.append("Domain is well-established")
        else:
            details.append("Domain is newly registered or age unknown")

        if scores['ssl_cert'] > 0:
            details.append("Valid SSL certificate")
        else:
            details.append("Invalid or missing SSL certificate")

        if scores['url_structure'] > 0.1:
            details.append("Clean URL structure")
        else:
            details.append("Suspicious URL structure detected")

        if scores['blacklist'] > 0:
            details.append("Not found in blacklist")
        else:
            details.append("Domain is blacklisted")

        if scores['typosquatting'] > 0.15:
            details.append("No typosquatting detected")
        else:
            details.append("Possible typosquatting attempt")

        # Get domain creation date
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}".lower()
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                domain_age_text = f"Domain Creation Date: {creation_date.strftime('%Y-%m-%d') if hasattr(creation_date, 'strftime') else creation_date}"
            else:
                domain_age_text = "Domain Creation Date: Unknown"
        except Exception:
            domain_age_text = "Domain Creation Date: Unknown"

        # Create description text with updated safety threshold
        description = f"Analysis for: {url}\n"
        description += f"Overall Safety Score: {percentage:.1f}% "
        description += "(Safe)" if percentage >= 80 else "(UNSAFE)\n"
        description += "\nKey Findings: " + "; ".join(details)
        description += f"\n\n{domain_age_text}\n"  # <-- Add domain age info here

        # Update description panel
        self.description_text.config(state=tk.NORMAL)
        self.description_text.delete(1.0, tk.END)
        self.description_text.insert(tk.END, description)
        self.description_text.config(state=tk.DISABLED)

        # --- AI Analysing Report ---
        self.ai_report_text.config(state=tk.NORMAL)
        self.ai_report_text.delete(1.0, tk.END)
        ai_report = self.detector.ai_analyse_url(url, scores)
        self.ai_report_text.insert(tk.END, f"AI Verdict: {ai_report['verdict']}\n")
        self.ai_report_text.insert(tk.END, f"Explanation: {ai_report['explanation']}\n")
        self.ai_report_text.insert(tk.END, f"AI Score: {ai_report['score']*100:.1f}%")

        top_risks = self.detector.get_top_risks(scores)
        self.ai_report_text.insert(tk.END, "\nTop Risk Factors:\n")
        for risk in top_risks:
            self.ai_report_text.insert(tk.END, f"- {risk}\n")

        if ai_report['verdict'] != "Highly Safe":
            suggestion = self.detector.suggest_legit_domain(url)
            self.ai_report_text.insert(tk.END, f"\nDid you mean: {suggestion}?\n")

        category = self.detector.categorize_url(url)
        self.ai_report_text.insert(tk.END, f"\nCategory: {category}\n")

        self.ai_report_text.config(state=tk.DISABLED)

    def check_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL.")
            return

        self.status_var.set("Checking URL...")
        self.root.update()

        try:
            if self.detector.is_phishing(url) == "Rate limit exceeded":
                messagebox.showwarning("Warning", "Please wait before checking another URL.")
                return

            # Calculate and display safety scores
            scores = self.detector.calculate_safety_score(url)
            self.update_graph(scores)
            self.update_description(url, scores)

            total_score = sum(scores.values())
            percentage = total_score * 100

            if total_score < 0.8:  # Below 80% is considered unsafe
                result = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ⚠️ UNSAFE: {url} (Safety: {percentage:.1f}%)"
                messagebox.showwarning("Warning", f"This URL is UNSAFE! Safety Score: {percentage:.1f}%")
            else:
                result = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✓ Safe: {url} (Safety: {percentage:.1f}%)"
                messagebox.showinfo("Info", f"This URL appears to be safe. Safety Score: {percentage:.1f}%")

            self.url_listbox.insert(0, result)
            self.url_entry.delete(0, tk.END)

        except Exception as e:
            logging.error(f"Error checking URL {url}: {str(e)}")
            messagebox.showerror("Error", "An error occurred while checking the URL.")
            self.description_text.config(state=tk.NORMAL)
            self.description_text.delete(1.0, tk.END)
            self.description_text.insert(tk.END, f"Error analyzing URL: {str(e)}")
            self.description_text.config(state=tk.DISABLED)

        finally:
            self.status_var.set("Ready")

    def clear_history(self):
        self.url_listbox.delete(0, tk.END)
        # Clear the graph
        self.figure.clear()
        self.canvas.draw()
        # Clear the description
        self.description_text.config(state=tk.NORMAL)
        self.description_text.delete(1.0, tk.END)
        self.description_text.config(state=tk.DISABLED)
        # Clear the AI report
        self.ai_report_text.config(state=tk.NORMAL)
        self.ai_report_text.delete(1.0, tk.END)
        self.ai_report_text.config(state=tk.DISABLED)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PhishingDetectorGUI()
    app.run()
