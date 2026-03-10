import datetime
import os
import platform
import re
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "Audit Tool - ISO/IEC 27001:2022 (Annex A Controls)"


class SimplePDFWriter:
	"""Small, dependency-free PDF writer for plain text reports."""

	def __init__(self, page_width=595, page_height=842, margin=50, line_height=14, font_size=10):
		self.page_width = page_width
		self.page_height = page_height
		self.margin = margin
		self.line_height = line_height
		self.font_size = font_size
		# Courier font: approximately 6 units per character at 10pt
		self.char_width = self.font_size * 0.6
		self.max_chars_per_line = int((page_width - 2 * margin) / self.char_width)

	@staticmethod
	def _escape_pdf_text(text):
		return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

	def _wrap_text(self, text):
		"""Wrap long lines to fit within page width."""
		if len(text) <= self.max_chars_per_line:
			return [text]
		
		wrapped = []
		while text:
			if len(text) <= self.max_chars_per_line:
				wrapped.append(text)
				break
			
			# Try to break at a space
			break_point = text.rfind(' ', 0, self.max_chars_per_line)
			if break_point == -1:
				# No space found, force break
				break_point = self.max_chars_per_line
			
			wrapped.append(text[:break_point])
			text = text[break_point:].lstrip()
		
		return wrapped

	def _paginate(self, lines):
		# First, wrap all lines
		wrapped_lines = []
		for line in lines:
			wrapped_lines.extend(self._wrap_text(line))
		
		usable_height = self.page_height - (2 * self.margin)
		lines_per_page = max(1, usable_height // self.line_height)
		pages = []
		for i in range(0, len(wrapped_lines), lines_per_page):
			pages.append(wrapped_lines[i : i + lines_per_page])
		return pages or [[""]]

	def write_text_pdf(self, file_path, lines):
		pages = self._paginate(lines)
		objects = []

		# 1: Catalog, 2: Pages
		objects.append("<< /Type /Catalog /Pages 2 0 R >>")

		kids = []
		next_obj_number = 3
		content_obj_numbers = []
		page_obj_numbers = []

		for _ in pages:
			page_obj_numbers.append(next_obj_number)
			kids.append(f"{next_obj_number} 0 R")
			next_obj_number += 1

			content_obj_numbers.append(next_obj_number)
			next_obj_number += 1

		objects.append(
			f"<< /Type /Pages /Count {len(pages)} /Kids [{' '.join(kids)}] >>"
		)

		content_map = dict(zip(page_obj_numbers, content_obj_numbers))

		for page_index, page_lines in enumerate(pages):
			page_obj_number = page_obj_numbers[page_index]
			content_obj_number = content_map[page_obj_number]

			objects.append(
				"<< /Type /Page /Parent 2 0 R "
				f"/MediaBox [0 0 {self.page_width} {self.page_height}] "
				"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> "
				f"/Contents {content_obj_number} 0 R >>"
			)

			y = self.page_height - self.margin
			content_lines = ["BT", f"/F1 {self.font_size} Tf"]
			for line in page_lines:
				text = self._escape_pdf_text(line)
				content_lines.append(f"1 0 0 1 {self.margin} {y} Tm ({text}) Tj")
				y -= self.line_height
			content_lines.append("ET")
			stream_data = "\n".join(content_lines).encode("latin-1", errors="replace")
			stream = (
				f"<< /Length {len(stream_data)} >>\nstream\n".encode("latin-1")
				+ stream_data
				+ b"\nendstream"
			)
			objects.append(stream)

		with open(file_path, "wb") as f:
			f.write(b"%PDF-1.4\n")
			offsets = [0]

			for i, obj in enumerate(objects, start=1):
				offsets.append(f.tell())
				f.write(f"{i} 0 obj\n".encode("latin-1"))
				if isinstance(obj, bytes):
					f.write(obj)
					f.write(b"\n")
				else:
					f.write(obj.encode("latin-1"))
					f.write(b"\n")
				f.write(b"endobj\n")

			xref_position = f.tell()
			f.write(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
			f.write(b"0000000000 65535 f \n")
			for off in offsets[1:]:
				f.write(f"{off:010d} 00000 n \n".encode("latin-1"))

			trailer = (
				f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
				f"startxref\n{xref_position}\n%%EOF"
			)
			f.write(trailer.encode("latin-1"))


class AuditApp:
	def __init__(self, root):
		self.root = root
		self.root.title(APP_TITLE)
		self.root.geometry("1000x680")
		self.root.minsize(900, 600)

		self._set_icon()
		self._configure_style()

		self.scanned_logs = []
		self.findings = []
		self.last_report_text = ""

		self.keyword_rules = [
            # ========== THEME 5: ORGANIZATIONAL CONTROLS (37 controls) ==========
            
            # 5.1 — Policies for Information Security
            {
                "name": "Policy Violations (5.1 Organizational)",
                "regex": r"policy.*violat|information security policy|acceptable.*use.*violat",
                "severity": "MEDIUM",
                "iso": "Control 5.1 (Policies for Information Security) - Organizational",
                "recommendation": "Review and enforce information security policies per 5.1. Ensure policy communication per Clause 7.3. Take disciplinary action if required.",
            },
            
            # 5.7 — Threat Intelligence (NEW in 2022)
            {
                "name": "Threat Intelligence Indicators (5.7 Organizational - NEW)",
                "regex": r"threat intelligence|TTPs|indicators of compromise|IOC|threat actor|APT|threat feed",
                "severity": "MEDIUM",
                "iso": "Control 5.7 (Threat Intelligence) - NEW in 2022 - Organizational",
                "recommendation": "Document threat intelligence collection and analysis per 5.7. Integrate CTI feeds, MISP, and threat actor profiles. Ensure actionable intel reaches SecOps.",
            },
            
            # 5.15-5.18 — Access Control (from old A.9)
            {
                "name": "Authentication Failures (5.15-5.18 Organizational)",
                "regex": r"failed password|authentication failure|logon failure|invalid user|login failed|auth.*fail",
                "severity": "HIGH",
                "iso": "Controls 5.15-5.18 (Access Control) - Organizational",
                "recommendation": "Review identity management per 5.15-5.16. Implement strong authentication per 5.17. Enforce access rights per 5.18. Deploy MFA where missing.",
            },
            {
                "name": "Privilege Escalation Activity (5.18 Organizational)",
                "regex": r"sudo|privilege.*escalat|admin rights|root access|elevation|become root|UAC",
                "severity": "HIGH",
                "iso": "Control 5.18 (Access Rights) - Organizational",
                "recommendation": "Verify least-privilege principle per 5.18. All privileged access must be logged, justified, and reviewed. Ensure privileged identity management.",
            },
            {
                "name": "Unauthorized Access Attempts (5.15-5.18 Organizational)",
                "regex": r"unauthorized|access denied|permission denied|forbidden|401|403",
                "severity": "MEDIUM",
                "iso": "Controls 5.15-5.18 (Access Control) - Organizational",
                "recommendation": "Review access control policy per 5.15-5.16. Ensure need-to-know and least privilege per 5.18. Document unauthorized access patterns.",
            },
            
            # 5.19-5.22 — Supplier Relationships (from old A.15)
            {
                "name": "Third-Party/Supplier Security Issues (5.19-5.22 Organizational)",
                "regex": r"third.?party.*fail|supplier.*breach|vendor.*security|external.*access.*unauthor",
                "severity": "MEDIUM",
                "iso": "Controls 5.19-5.22 (Supplier Relationships) - Organizational",
                "recommendation": "Review supplier security per 5.19-5.21. Monitor third-party access per 5.20. Ensure supply chain security per 5.22 (addressing in agreements).",
            },
            
            # 5.23 — Information Security for Cloud Services (NEW in 2022)
            {
                "name": "Cloud Service Security Issues (5.23 Organizational - NEW)",
                "regex": r"cloud.*security|AWS|Azure|GCP|S3.*bucket|cloud.*misconfigur|SaaS.*breach",
                "severity": "HIGH",
                "iso": "Control 5.23 (Information Security for Cloud Services) - NEW in 2022 - Organizational",
                "recommendation": "Review cloud security controls per 5.23. Cover acquisition, use, management, and EXIT of cloud services. Ensure shared responsibility model is documented.",
            },
            
            # 5.24-5.28 — Incident Management (from old A.16)
            {
                "name": "Security Incident Indicators (5.24-5.28 Organizational)",
                "regex": r"security incident|breach|compromised|intrusion detected|attack|incident response",
                "severity": "HIGH",
                "iso": "Controls 5.24-5.28 (Incident Management) - Organizational",
                "recommendation": "Follow incident procedures per 5.24-5.26. Collect evidence per 5.27. Conduct lessons learned per 5.28. Report through defined channels.",
            },
            
            # 5.29-5.30 — Business Continuity (from old A.17)
            {
                "name": "Service Availability Failures (5.29-5.30 Organizational)",
                "regex": r"service.*fail|service.*crash|kernel panic|critical error|system.*down|outage",
                "severity": "HIGH",
                "iso": "Controls 5.29-5.30 (Business Continuity) - Organizational",
                "recommendation": "Verify continuity planning per 5.29. Check ICT readiness per 5.30 (NEW control). Test continuity procedures. Document incident per 5.24-5.28.",
            },
            
            # 5.31-5.37 — Compliance (from old A.18)
            {
                "name": "Compliance/Legal Violations (5.31-5.37 Organizational)",
                "regex": r"compliance.*violation|policy.*violation|regulation.*breach|audit.*fail|non-compliant|GDPR|privacy.*breach",
                "severity": "HIGH",
                "iso": "Controls 5.31-5.37 (Compliance) - Organizational",
                "recommendation": "Address compliance gaps per 5.31-5.36. Review legal/regulatory requirements. Ensure privacy protection per 5.34. Document corrective actions per Clause 10.2.",
            },
            
            # ========== THEME 6: PEOPLE CONTROLS (8 controls) ==========
            
            # 6.x — Human Resource Security (from old A.7)
            {
                "name": "User Account Lifecycle Issues (6.6 People)",
                "regex": r"terminated.*user|suspended.*account|dormant.*account|inactive.*user|user.*removal.*fail",
                "severity": "MEDIUM",
                "iso": "Control 6.6 (Confidentiality or Non-Disclosure Agreements) - People",
                "recommendation": "Review termination procedures per 6.6-6.8 (during/after employment). Ensure access rights removed promptly. Disable dormant accounts.",
            },
            
            # ========== THEME 7: PHYSICAL CONTROLS (14 controls) ==========
            
            # 7.x — Physical Security (from old A.11)
            {
                "name": "Physical Security Events (7.1-7.3 Physical)",
                "regex": r"physical.*breach|door.*forced|unauthorized.*entry|badge.*fail|intrusion.*alarm",
                "severity": "HIGH",
                "iso": "Controls 7.1-7.3 (Physical Security) - Physical",
                "recommendation": "Review physical access controls per 7.2. Verify secure areas per 7.1. Check physical entry controls per 7.3. Investigate immediately.",
            },
            
            # 7.4 — Physical Security Monitoring (NEW in 2022)
            {
                "name": "Physical Security Monitoring (7.4 Physical - NEW)",
                "regex": r"CCTV|surveillance|camera.*offline|video.*monitor|physical.*surveillance",
                "severity": "MEDIUM",
                "iso": "Control 7.4 (Physical Security Monitoring) - NEW in 2022 - Physical",
                "recommendation": "Ensure continuous physical security monitoring per 7.4. CCTV/surveillance systems must be operational. Review footage retention and access controls.",
            },
            
            # ========== THEME 8: TECHNOLOGICAL CONTROLS (34 controls) ==========
            
            # 8.2-8.5 — Access Control Technical (from old A.9)
            {
                "name": "Access Control Technical Issues (8.2-8.5 Technological)",
                "regex": r"access.*revocation.*fail|credential.*compromise|token.*expir|session.*timeout.*fail",
                "severity": "HIGH",
                "iso": "Controls 8.2-8.5 (Privileged Access & Access Control) - Technological",
                "recommendation": "Review privileged access rights per 8.2. Enforce secure authentication per 8.5. Manage access restrictions per 8.3-8.4.",
            },
            
            # 8.7 — Protection Against Malware (from old A.12.2)
            {
                "name": "Malware Detection/Threat Indicators (8.7 Technological)",
                "regex": r"malware|virus|trojan|ransomware|defender detected|threat|infected|quarantine|suspicious file",
                "severity": "HIGH",
                "iso": "Control 8.7 (Protection Against Malware) - Technological",
                "recommendation": "Isolate affected systems per 5.24-5.28 (Incident Management). Verify malware protection per 8.7. Update signatures and perform forensic analysis.",
            },
            
            # 8.8 — Management of Technical Vulnerabilities (evolved from A.12.6)
            {
                "name": "Vulnerability/Patch Management (8.8 Technological)",
                "regex": r"vulnerability|CVE-|patch.*fail|update.*fail|unpatched|exploit|zero.?day",
                "severity": "HIGH",
                "iso": "Control 8.8 (Management of Technical Vulnerabilities) - Technological",
                "recommendation": "Full vulnerability lifecycle per 8.8: identify → evaluate exposure → take action → document. Apply patches promptly. Track compliance and exceptions.",
            },
            
            # 8.9 — Configuration Management (NEW in 2022)
            {
                "name": "Configuration Management Violations (8.9 Technological - NEW)",
                "regex": r"configuration.*drift|baseline.*violation|hardening.*fail|unauthorized.*config|CIS.*benchmark",
                "severity": "HIGH",
                "iso": "Control 8.9 (Configuration Management) - NEW in 2022 - Technological",
                "recommendation": "Maintain security baseline configurations per 8.9. Apply CIS Benchmarks, DISA STIGs. Document exceptions. Monitor for configuration drift.",
            },
            
            # 8.10 — Information Deletion (NEW in 2022)
            {
                "name": "Data Deletion/Retention Violations (8.10 Technological - NEW)",
                "regex": r"data.*retention.*violat|deletion.*fail|securely.*wipe|data.*sanitization|GDPR.*right.*erasure",
                "severity": "MEDIUM",
                "iso": "Control 8.10 (Information Deletion) - NEW in 2022 - Technological",
                "recommendation": "Ensure secure deletion per 8.10. Implement data sanitization procedures. Align with retention schedules and privacy regulations (GDPR right to erasure).",
            },
            
            # 8.11 — Data Masking (NEW in 2022)
            {
                "name": "Data Masking/Anonymization Issues (8.11 Technological - NEW)",
                "regex": r"PII.*expos|personal.*data.*leak|masking.*fail|anonymization|pseudonymization",
                "severity": "HIGH",
                "iso": "Control 8.11 (Data Masking) - NEW in 2022 - Technological",
                "recommendation": "Apply data masking per 8.11 for non-production environments. Anonymize/pseudonymize PII. Prevent exposure in logs, dev/test systems.",
            },
            
            # 8.12 — Data Leakage Prevention (NEW in 2022)
            {
                "name": "Data Leakage/Exfiltration (8.12 Technological - NEW)",
                "regex": r"data.*leak|data.*exfiltration|DLP.*alert|sensitive.*data.*transfer|unauthorized.*download",
                "severity": "HIGH",
                "iso": "Control 8.12 (Data Leakage Prevention) - NEW in 2022 - Technological",
                "recommendation": "Implement DLP controls per 8.12. Monitor and prevent unauthorized data transfers. Investigate exfiltration attempts immediately.",
            },
            
            # 8.13 — Information Backup (from old A.12.3)
            {
                "name": "Backup Failures (8.13 Technological)",
                "regex": r"backup.*fail|backup.*error|restore.*fail|snapshot.*fail",
                "severity": "HIGH",
                "iso": "Control 8.13 (Information Backup) - Technological",
                "recommendation": "Test backup restoration per 8.13. Impacts business continuity (5.29-5.30). Review backup policy and retention schedules. Ensure tested recovery.",
            },
            
            # 8.15 — Logging (from old A.12.4)
            {
                "name": "Logging/Monitoring Failures (8.15 Technological)",
                "regex": r"audit disabled|logging disabled|auditd stopped|eventlog stopped|log.*fail|syslog.*error",
                "severity": "HIGH",
                "iso": "Control 8.15 (Logging) - Technological",
                "recommendation": "Critical control failure. Re-enable logging immediately per 8.15. All security events must be logged and protected. Investigate root cause.",
            },
            
            # 8.16 — Monitoring Activities (NEW in 2022)
            {
                "name": "Anomaly Detection/Monitoring Gaps (8.16 Technological - NEW)",
                "regex": r"anomaly.*detect|SIEM.*alert|UEBA|behavioral.*analysis|abnormal.*activity",
                "severity": "MEDIUM",
                "iso": "Control 8.16 (Monitoring Activities) - NEW in 2022 - Technological",
                "recommendation": "Monitor for anomalous behaviour per 8.16. Deploy SIEM/UEBA for behaviour analytics. Networks, systems, applications must be continuously monitored.",
            },
            
            # 8.19 — Capacity Management (from old A.12.1.3)
            {
                "name": "Capacity/Performance Issues (8.19 Technological)",
                "regex": r"out of memory|disk full|cpu overload|capacity.*exceeded|performance.*degrad",
                "severity": "MEDIUM",
                "iso": "Control 8.19 (Installation of Software on Operational Systems) - Technological",
                "recommendation": "Monitor capacity to ensure availability. Review capacity planning and forecasting. May impact business continuity (5.29-5.30).",
            },
            
            # 8.20-8.22 — Network Security (from old A.13)
            {
                "name": "Network Security Violations (8.20-8.22 Technological)",
                "regex": r"firewall.*block|firewall.*deny|network.*denied|connection refused|port scan|iptables.*drop|ufw.*deny",
                "severity": "MEDIUM",
                "iso": "Controls 8.20-8.22 (Network Security) - Technological",
                "recommendation": "Review network controls per 8.20-8.21. Verify network segregation per 8.22. Ensure blocked traffic aligns with security policy.",
            },
            {
                "name": "Information Transfer Issues (8.20-8.22 Technological)",
                "regex": r"transfer.*fail|transmission.*error|file.*transfer.*denied",
                "severity": "MEDIUM",
                "iso": "Controls 8.20-8.22 (Network Security) - Technological",
                "recommendation": "Review secure information transfer per 8.20-8.21. Ensure secure transfer mechanisms and encryption where required.",
            },
            
            # 8.23 — Web Filtering (NEW in 2022)
            {
                "name": "Web Filtering Violations (8.23 Technological - NEW)",
                "regex": r"web.*filter|blocked.*website|proxy.*violation|malicious.*URL|phishing.*URL",
                "severity": "MEDIUM",
                "iso": "Control 8.23 (Web Filtering) - NEW in 2022 - Technological",
                "recommendation": "Enforce web filtering per 8.23. Block malicious URLs, phishing sites, and unauthorized categories. Review proxy/filter logs regularly.",
            },
            
            # 8.24 — Cryptography (from old A.10)
            {
                "name": "Cryptographic Control Issues (8.24 Technological)",
                "regex": r"encryption.*fail|decrypt.*error|certificate.*error|certificate.*expir|TLS.*error|SSL.*error|crypto.*fail",
                "severity": "HIGH",
                "iso": "Control 8.24 (Use of Cryptography) - Technological",
                "recommendation": "Review cryptographic policy per 8.24. Verify key management practices. Rotate expired certificates immediately. Enforce strong encryption.",
            },
            
            # 8.25-8.34 — Secure Development (from old A.14)
            {
                "name": "Development/Change Control Issues (8.25-8.34 Technological)",
                "regex": r"unauthorized.*change|change.*control.*fail|development.*security|code.*injection|sql.*injection",
                "severity": "HIGH",
                "iso": "Controls 8.25-8.34 (Secure Development Lifecycle) - Technological",
                "recommendation": "Review secure SDLC per 8.25-8.34. Ensure change control per 8.32. Test security before deployment per 8.29. Outsourced development per 8.30.",
            },
            
            # 8.28 — Secure Coding (NEW in 2022)
            {
                "name": "Secure Coding Violations (8.28 Technological - NEW)",
                "regex": r"insecure.*code|code.*vulnerabilit|SAST|DAST|secure.*coding|OWASP",
                "severity": "HIGH",
                "iso": "Control 8.28 (Secure Coding) - NEW in 2022 - Technological",
                "recommendation": "Apply secure coding principles per 8.28. Use SAST/DAST tools. Follow OWASP guidelines. Train developers in secure coding practices.",
            },
		]

		self._build_layout()

	def _set_icon(self):
		# Create a simple built-in icon so the app has a taskbar icon on both Windows and Linux.
		icon = tk.PhotoImage(width=16, height=16)
		icon.put("#103a5e", to=(0, 0, 16, 16))
		icon.put("#4cb5f5", to=(2, 2, 14, 14))
		icon.put("#0a2033", to=(5, 5, 11, 11))
		self.root.iconphoto(True, icon)
		self.root._icon_ref = icon

	def _configure_style(self):
		style = ttk.Style()
		if "vista" in style.theme_names():
			style.theme_use("vista")
		elif "clam" in style.theme_names():
			style.theme_use("clam")

		style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
		style.configure("Muted.TLabel", foreground="#555555")
		style.configure("Summary.TLabel", font=("Segoe UI", 10, "bold"))

	def _build_layout(self):
		root_frame = ttk.Frame(self.root, padding=12)
		root_frame.pack(fill=tk.BOTH, expand=True)

		header = ttk.Frame(root_frame)
		header.pack(fill=tk.X, pady=(0, 10))

		ttk.Label(header, text="Audit Tool", style="Title.TLabel").pack(anchor=tk.W)
		ttk.Label(
			header,
            text="ISO/IEC 27001:2022 Annex A controls analysis (93 controls in 4 themes) for Windows and Linux",
            style="Muted.TLabel",
		).pack(anchor=tk.W)

		controls = ttk.LabelFrame(root_frame, text="Controls", padding=10)
		controls.pack(fill=tk.X)

		self.os_choice = tk.StringVar(value="auto")
		ttk.Radiobutton(controls, text="Auto Detect", variable=self.os_choice, value="auto").grid(
			row=0, column=0, padx=(0, 10), sticky=tk.W
		)
		ttk.Radiobutton(controls, text="Windows", variable=self.os_choice, value="windows").grid(
			row=0, column=1, padx=(0, 10), sticky=tk.W
		)
		ttk.Radiobutton(controls, text="Linux", variable=self.os_choice, value="linux").grid(
			row=0, column=2, padx=(0, 10), sticky=tk.W
		)

		self.status_var = tk.StringVar(value="Ready")
		ttk.Label(controls, textvariable=self.status_var, style="Muted.TLabel").grid(
			row=0, column=3, sticky=tk.E
		)
		controls.columnconfigure(3, weight=1)

		button_row = ttk.Frame(controls)
		button_row.grid(row=1, column=0, columnspan=4, pady=(10, 0), sticky=tk.W)

		ttk.Button(button_row, text="Run Audit", command=self.run_audit).pack(side=tk.LEFT, padx=(0, 8))
		ttk.Button(button_row, text="Save Report as PDF", command=self.save_pdf).pack(side=tk.LEFT, padx=(0, 8))
		ttk.Button(button_row, text="Clear", command=self.clear_output).pack(side=tk.LEFT)

		summary = ttk.LabelFrame(root_frame, text="Summary", padding=10)
		summary.pack(fill=tk.X, pady=(10, 0))

		self.summary_var = tk.StringVar(value="No audit run yet.")
		ttk.Label(summary, textvariable=self.summary_var, style="Summary.TLabel").pack(anchor=tk.W)

		output_frame = ttk.LabelFrame(root_frame, text="Audit Findings", padding=6)
		output_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

		self.output = tk.Text(output_frame, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED)
		self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

		scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output.yview)
		scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
		self.output.configure(yscrollcommand=scrollbar.set)

		footer = ttk.Label(
			root_frame,
			text="Made by Param Kalaria",
			style="Muted.TLabel",
		)
		footer.pack(anchor=tk.E, pady=(8, 0))

	def append_output(self, text):
		self.output.configure(state=tk.NORMAL)
		self.output.insert(tk.END, text + "\n")
		self.output.see(tk.END)
		self.output.configure(state=tk.DISABLED)

	def clear_output(self):
		self.output.configure(state=tk.NORMAL)
		self.output.delete("1.0", tk.END)
		self.output.configure(state=tk.DISABLED)
		self.summary_var.set("Output cleared.")
		self.status_var.set("Ready")

	def detect_target_os(self):
		selected = self.os_choice.get()
		if selected != "auto":
			return selected
		return "windows" if platform.system().lower().startswith("win") else "linux"

	def run_audit(self):
		self.status_var.set("Running audit...")
		self.summary_var.set("Collecting logs and analyzing controls...")
		self.clear_output()

		audit_thread = threading.Thread(target=self._run_audit_background, daemon=True)
		audit_thread.start()

	def _run_audit_background(self):
		target_os = self.detect_target_os()
		timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		self._ui_call(self.append_output, f"[{timestamp}] Starting audit for {target_os.upper()}...")

		if target_os == "windows":
			logs = self._collect_windows_logs()
		else:
			logs = self._collect_linux_logs()

		self.scanned_logs = logs
		findings = self._analyze_logs(logs)
		self.findings = findings

		report_text = self._format_report(target_os, logs, findings)
		self.last_report_text = report_text
		self._ui_call(self.append_output, report_text)

		high_count = sum(1 for item in findings if item["severity"] == "HIGH")
		medium_count = sum(1 for item in findings if item["severity"] == "MEDIUM")
		low_count = sum(1 for item in findings if item["severity"] == "LOW")

		summary = (
			f"Audit complete. Findings: {len(findings)} "
			f"(HIGH={high_count}, MEDIUM={medium_count}, LOW={low_count})"
		)
		self._ui_call(self._set_status, "Audit complete")
		self._ui_call(self.summary_var.set, summary)

		if high_count > 0:
			self._ui_call(
				messagebox.showwarning,
				"High Severity Alert",
				f"{high_count} high-severity findings detected. Review report immediately.",
			)
		else:
			self._ui_call(
				messagebox.showinfo,
				"Audit Finished",
				"Audit finished successfully with no high-severity findings.",
			)

	def _set_status(self, status):
		self.status_var.set(status)

	def _ui_call(self, func, *args):
		self.root.after(0, lambda: func(*args))

	def _collect_windows_logs(self):
		channels = ["Security", "System", "Application"]
		all_lines = []

		for channel in channels:
			cmd = ["wevtutil", "qe", channel, "/f:text", "/c:400"]
			try:
				result = subprocess.run(
					cmd,
					capture_output=True,
					text=True,
					timeout=30,
					check=False,
					encoding="utf-8",
					errors="ignore",
				)
				if result.stdout:
					all_lines.extend(result.stdout.splitlines())
				if result.stderr:
					all_lines.append(f"[WARN] {channel}: {result.stderr.strip()}")
			except FileNotFoundError:
				all_lines.append("[ERROR] wevtutil not found. Cannot read Windows Event Logs.")
				break
			except subprocess.TimeoutExpired:
				all_lines.append(f"[WARN] Timeout while reading {channel} log.")

		return all_lines

	def _collect_linux_logs(self):
		candidate_paths = [
			"/etc/log",
			"/var/log",
		]
		all_lines = []

		chosen_base = None
		for path in candidate_paths:
			if os.path.exists(path):
				chosen_base = path
				break

		if not chosen_base:
			return ["[ERROR] Neither /etc/log nor /var/log exists on this system."]

		all_lines.append(f"[INFO] Reading Linux logs from: {chosen_base}")
		for root, _dirs, files in os.walk(chosen_base):
			for name in files:
				file_path = os.path.join(root, name)
				if not re.search(r"log|syslog|auth|secure|kern|messages|audit", name, re.IGNORECASE):
					continue

				try:
					with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
						content = f.readlines()[-300:]
					all_lines.extend([f"{file_path}: {line.rstrip()}" for line in content])
				except PermissionError:
					all_lines.append(f"[WARN] Permission denied: {file_path}")
				except OSError as ex:
					all_lines.append(f"[WARN] Failed to read {file_path}: {ex}")

		if len(all_lines) == 1 and all_lines[0].startswith("[INFO]"):
			all_lines.append("[WARN] No matching log files found for analysis.")

		return all_lines

	def _analyze_logs(self, logs):
		findings = []

		for rule in self.keyword_rules:
			pattern = re.compile(rule["regex"], flags=re.IGNORECASE)
			matches = [line for line in logs if pattern.search(line)]
			if matches:
				findings.append(
					{
						"control": rule["name"],
						"severity": rule["severity"],
						"iso": rule["iso"],
						"count": len(matches),
						"sample": matches[:3],
						"recommendation": rule["recommendation"],
					}
				)

		if not findings:
			findings.append(
				{
					"control": "No direct keyword-based violations found",
					"severity": "LOW",
                    "iso": "ISO/IEC 27001:2022 Baseline Check",
                    "count": 0,
                    "sample": ["No suspicious patterns detected in current sampling scope."],
                    "recommendation": "Schedule periodic internal audits per Clause 9.2.1-9.2.2. Extend rules based on risk assessment (Clause 6.1.2). Update Statement of Applicability (Clause 6.1.3d).",
				}
			)

		severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
		findings.sort(key=lambda item: severity_rank.get(item["severity"], 0), reverse=True)
		return findings

	def _format_report(self, target_os, logs, findings):
		now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		lines = [
			"=" * 90,
			APP_TITLE,
			f"Timestamp: {now}",
			f"Target OS: {target_os.upper()}",
			f"Total log lines processed: {len(logs)}",
			"=" * 90,
			"",
			"Findings:",
		]

		for index, item in enumerate(findings, start=1):
			lines.append(f"{index}. {item['control']}")
			lines.append(f"   Severity: {item['severity']}")
			lines.append(f"   ISO Mapping: {item['iso']}")
			lines.append(f"   Matched Events: {item['count']}")
			lines.append(f"   Recommendation: {item['recommendation']}")
			lines.append("   Sample Events:")
			for sample in item["sample"]:
				trimmed = sample.strip()
				if len(trimmed) > 180:
					trimmed = trimmed[:177] + "..."
				lines.append(f"   - {trimmed}")
			lines.append("")

		lines.append("")
		lines.append("ISO/IEC 27001:2022 Context:")
		lines.append("- This audit maps findings to the 4-theme Annex A structure (2022 edition): 5-Organizational, 6-People, 7-Physical, 8-Technological.")
		lines.append("- 93 controls (down from 114 in 2013). Includes 11 NEW controls: 5.7 (Threat Intel), 5.23 (Cloud), 5.30 (ICT Readiness),")
		lines.append("  7.4 (Physical Monitoring), 8.9 (Config Mgmt), 8.10 (Data Deletion), 8.11 (Masking), 8.12 (DLP), 8.16 (Monitoring), 8.23 (Web Filter), 8.28 (Secure Coding).")
		lines.append("- Findings should inform your Risk Treatment Plan (Clause 6.1.3) and Statement of Applicability (Clause 6.1.3d).")
		lines.append("- Follow PDCA cycle: Plan (risk assessment) -> Do (implement controls) -> Check (audit) -> Act (improve per Clause 10.1).")
		lines.append("- High-severity findings may require corrective action per Clause 10.2 (was 10.1 in 2013 - order reversed).")
		lines.append("")
		lines.append("Notes:")
		lines.append("- This is a keyword-driven technical audit. Pair with management reviews (Clause 9.3.1-9.3.3) and internal audits (Clause 9.2.1-9.2.2).")
		lines.append("- Update risk assessment per Clause 6.1.2 based on findings. Plan changes systematically per Clause 6.3 (NEW in 2022).")
		lines.append("- Some log files (especially Linux) may require elevated permissions to access.")
		lines.append("- Not all 93 Annex A controls are detectable via logs; organizational/procedural controls require separate assessment.")
		lines.append("- This edition (2022) replaces ISO/IEC 27001:2013. Transition deadline was October 31, 2025.")
		lines.append("")
		lines.append("Made by Param Kalaria")

		return "\n".join(lines)

	def save_pdf(self):
		if not self.last_report_text.strip():
			messagebox.showinfo("No Report", "Run an audit before exporting a PDF report.")
			return

		default_name = f"audit_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
		file_path = filedialog.asksaveasfilename(
			title="Save Audit Report as PDF",
			defaultextension=".pdf",
			initialfile=default_name,
			filetypes=[("PDF files", "*.pdf")],
		)
		if not file_path:
			return

		try:
			writer = SimplePDFWriter()
			writer.write_text_pdf(file_path, self.last_report_text.splitlines())
			self.status_var.set(f"Saved PDF: {os.path.basename(file_path)}")
			messagebox.showinfo("Saved", f"Report saved successfully:\n{file_path}")
		except OSError as ex:
			messagebox.showerror("Save Error", f"Failed to save PDF report.\n{ex}")


def main():
	root = tk.Tk()
	app = AuditApp(root)
	root.mainloop()


if __name__ == "__main__":
	main()
