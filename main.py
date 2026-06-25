import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# Import local modules
from analyzer import PasswordAnalyzer
from password_generator import PasswordGenerator
from report import AuditReporter

# Theme Color Palette (Sleek Dark Cyber Style)
COLOR_BG = "#0B0F19"         # Slate-950 (Main window background)
COLOR_CARD = "#151D30"       # Slate-900 (Container/card background)
COLOR_CARD_BORDER = "#243354"# Slate-800 border
COLOR_TEXT_MAIN = "#F1F5F9"  # Slate-100 (Primary text)
COLOR_TEXT_MUTED = "#94A3B8" # Slate-400 (Secondary/labels text)
COLOR_ACCENT = "#06B6D4"     # Cyan (Active highlight)
COLOR_ACCENT_HOVER = "#0891B2"

# Rating Colors
COLOR_VERY_WEAK = "#EF4444"  # Red
COLOR_WEAK = "#F97316"       # Orange
COLOR_FAIR = "#EAB308"       # Yellow
COLOR_GOOD = "#10B981"       # Emerald Green
COLOR_STRONG = "#06B6D4"     # Cyan
COLOR_EXCELLENT = "#3B82F6"  # Royal Blue

class WiFiSecurityAuditorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Wi-Fi Password Security Auditor")
        self.root.geometry("1100x700")
        self.root.minsize(1000, 650)
        self.root.configure(bg=COLOR_BG)

        # Initialize Backend Workers
        self.analyzer = PasswordAnalyzer()
        self.generator = PasswordGenerator()

        # Application state variables
        self.active_tab = "auditor"
        self.password_visible = False
        self.generated_password = tk.StringVar()
        self.last_analysis_results = None
        self.last_password_analyzed = ""

        # Gauge Animation properties
        self.anim_target_score = 0
        self.anim_current_score = 0.0
        self.anim_step = 2.0
        self.anim_timer_id = None

        self._setup_styles()
        self._build_layout()
        self._show_frame("auditor")

    def _setup_styles(self) -> None:
        """Configures ttk styles for consistent theme execution."""
        style = ttk.Style()
        style.theme_use("clam")

        # Configure TFrame
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Card.TFrame", background=COLOR_CARD, borderwidth=1, relief="solid")

        # Configure Entry
        style.configure("TEntry", fieldbackground=COLOR_CARD, foreground=COLOR_TEXT_MAIN, 
                        bordercolor=COLOR_CARD_BORDER, lightcolor=COLOR_CARD_BORDER, darkcolor=COLOR_CARD_BORDER)
        
        # Configure Scrollbars
        style.configure("Vertical.TScrollbar", background=COLOR_CARD, troughcolor=COLOR_BG,
                        bordercolor=COLOR_CARD_BORDER, arrowcolor=COLOR_TEXT_MUTED)

        # Configure Labels
        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MAIN, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT_MAIN, font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MAIN, font=("Segoe UI", 16, "bold"))
        style.configure("CardTitle.TLabel", background=COLOR_CARD, foreground=COLOR_ACCENT, font=("Segoe UI", 11, "bold"))
        style.configure("Muted.TLabel", background=COLOR_BG, foreground=COLOR_TEXT_MUTED, font=("Segoe UI", 9))
        style.configure("CardMuted.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT_MUTED, font=("Segoe UI", 9))

        # Checkboxes/Radiobuttons
        style.configure("TCheckbutton", background=COLOR_CARD, foreground=COLOR_TEXT_MAIN, font=("Segoe UI", 9))
        style.map("TCheckbutton", background=[("active", COLOR_CARD)], foreground=[("active", COLOR_TEXT_MAIN)])
        
        style.configure("TRadiobutton", background=COLOR_CARD, foreground=COLOR_TEXT_MAIN, font=("Segoe UI", 9))
        style.map("TRadiobutton", background=[("active", COLOR_CARD)], foreground=[("active", COLOR_TEXT_MAIN)])

    def _build_layout(self) -> None:
        """Assembles the sidebar navigation and content frames."""
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        # ----------------- SIDEBAR PANEL -----------------
        self.sidebar = tk.Frame(self.root, bg=COLOR_CARD, width=220, bd=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_propagate(False)

        # Sidebar Title
        logo_label = tk.Label(self.sidebar, text="🛡  WIFI AUDITOR", fg=COLOR_TEXT_MAIN, bg=COLOR_CARD,
                              font=("Segoe UI", 14, "bold"))
        logo_label.pack(pady=(30, 40), padx=20, anchor="w")

        # Sidebar Menu Buttons
        self.btn_auditor = tk.Button(
            self.sidebar, text="  Password Auditor", fg=COLOR_TEXT_MAIN, bg=COLOR_CARD,
            activeforeground=COLOR_TEXT_MAIN, activebackground=COLOR_CARD_BORDER,
            font=("Segoe UI", 10, "bold"), bd=0, anchor="w", padx=20, pady=12,
            command=lambda: self._show_frame("auditor")
        )
        self.btn_auditor.pack(fill="x", padx=10, pady=2)

        self.btn_generator = tk.Button(
            self.sidebar, text="  Password Generator", fg=COLOR_TEXT_MUTED, bg=COLOR_CARD,
            activeforeground=COLOR_TEXT_MAIN, activebackground=COLOR_CARD_BORDER,
            font=("Segoe UI", 10, "bold"), bd=0, anchor="w", padx=20, pady=12,
            command=lambda: self._show_frame("generator")
        )
        self.btn_generator.pack(fill="x", padx=10, pady=2)

        self.btn_about = tk.Button(
            self.sidebar, text="  Security Notice", fg=COLOR_TEXT_MUTED, bg=COLOR_CARD,
            activeforeground=COLOR_TEXT_MAIN, activebackground=COLOR_CARD_BORDER,
            font=("Segoe UI", 10, "bold"), bd=0, anchor="w", padx=20, pady=12,
            command=lambda: self._show_frame("about")
        )
        self.btn_about.pack(fill="x", padx=10, pady=2)

        # Sidebar Footer (Disclaimer notice)
        disclaimer = tk.Label(
            self.sidebar, text="Defensive Tool\nAudits strengths only.\nNo cracking capability.",
            fg=COLOR_TEXT_MUTED, bg=COLOR_CARD, font=("Segoe UI", 8, "italic"), justify="center"
        )
        disclaimer.pack(side="bottom", pady=20, fill="x")

        # ----------------- MAIN CONTENT CONTAINER -----------------
        self.content_container = tk.Frame(self.root, bg=COLOR_BG)
        self.content_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.content_container.columnconfigure(0, weight=1)
        self.content_container.rowconfigure(0, weight=1)

        # Build individual frames
        self._build_auditor_frame()
        self._build_generator_frame()
        self._build_about_frame()

    def _show_frame(self, name: str) -> None:
        """Toggles the visible layout frame and active menu visual states."""
        self.active_tab = name
        
        # Hide all frames
        self.frame_auditor.grid_remove()
        self.frame_generator.grid_remove()
        self.frame_about.grid_remove()

        # Reset button styles
        self.btn_auditor.configure(fg=COLOR_TEXT_MUTED, bg=COLOR_CARD)
        self.btn_generator.configure(fg=COLOR_TEXT_MUTED, bg=COLOR_CARD)
        self.btn_about.configure(fg=COLOR_TEXT_MUTED, bg=COLOR_CARD)

        # Show frame & highlight active sidebar tab
        if name == "auditor":
            self.frame_auditor.grid(row=0, column=0, sticky="nsew")
            self.btn_auditor.configure(fg=COLOR_ACCENT, bg=COLOR_CARD_BORDER)
        elif name == "generator":
            self.frame_generator.grid(row=0, column=0, sticky="nsew")
            self.btn_generator.configure(fg=COLOR_ACCENT, bg=COLOR_CARD_BORDER)
        elif name == "about":
            self.frame_about.grid(row=0, column=0, sticky="nsew")
            self.btn_about.configure(fg=COLOR_ACCENT, bg=COLOR_CARD_BORDER)

    # =========================================================================
    # AUDITOR VIEW
    # =========================================================================
    def _build_auditor_frame(self) -> None:
        """Creates the layout structure for the Wi-Fi Password Auditor tab."""
        self.frame_auditor = tk.Frame(self.content_container, bg=COLOR_BG)
        self.frame_auditor.columnconfigure(0, weight=1)
        self.frame_auditor.rowconfigure(1, weight=1)

        # Header Title
        title_label = ttk.Label(self.frame_auditor, text="Wi-Fi Password Security Auditor", style="Title.TLabel")
        title_label.grid(row=0, column=0, sticky="w", pady=(0, 15))

        # --- Password Entry Row ---
        entry_card = tk.Frame(self.frame_auditor, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                              highlightthickness=1, relief="flat")
        entry_card.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        entry_card.columnconfigure(0, weight=1)

        input_label = tk.Label(entry_card, text="Enter Wi-Fi Password to Audit:", fg=COLOR_TEXT_MUTED, 
                               bg=COLOR_CARD, font=("Segoe UI", 9, "bold"))
        input_label.grid(row=0, column=0, sticky="w", padx=15, pady=(10, 2))

        # Password Entry
        self.ent_password = tk.Entry(
            entry_card, bg=COLOR_BG, fg=COLOR_TEXT_MAIN, insertbackground=COLOR_TEXT_MAIN,
            show="*", font=("Consolas", 12), bd=0, highlightthickness=1,
            highlightbackground=COLOR_CARD_BORDER, highlightcolor=COLOR_ACCENT
        )
        self.ent_password.grid(row=1, column=0, sticky="ew", padx=(15, 10), pady=(0, 15))
        self.ent_password.bind("<Return>", lambda e: self._perform_audit())

        # Visibility Toggle & Analyze Buttons container
        buttons_frame = tk.Frame(entry_card, bg=COLOR_CARD)
        buttons_frame.grid(row=1, column=1, sticky="e", padx=(0, 15), pady=(0, 15))

        self.btn_toggle_visibility = tk.Button(
            buttons_frame, text="👁 Show", bg=COLOR_CARD_BORDER, fg=COLOR_TEXT_MAIN,
            activebackground=COLOR_CARD, activeforeground=COLOR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"), bd=0, padx=12, pady=4, cursor="hand2",
            command=self._toggle_password_visibility
        )
        self.btn_toggle_visibility.grid(row=0, column=0, padx=(0, 10))

        btn_analyze = tk.Button(
            buttons_frame, text="Analyze Security", bg=COLOR_ACCENT, fg=COLOR_BG,
            activebackground=COLOR_ACCENT_HOVER, activeforeground=COLOR_BG,
            font=("Segoe UI", 9, "bold"), bd=0, padx=15, pady=4, cursor="hand2",
            command=self._perform_audit
        )
        btn_analyze.grid(row=0, column=1)

        # --- Dashboard Core Layout ---
        dashboard_scroll_frame = tk.Frame(self.frame_auditor, bg=COLOR_BG)
        dashboard_scroll_frame.grid(row=2, column=0, sticky="nsew")
        dashboard_scroll_frame.columnconfigure(0, weight=1)
        dashboard_scroll_frame.rowconfigure(0, weight=1)

        # Add vertical scrolling for smaller screen resolutions
        canvas = tk.Canvas(dashboard_scroll_frame, bg=COLOR_BG, bd=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(dashboard_scroll_frame, orient="vertical", command=canvas.yview)
        scroll_content = tk.Frame(canvas, bg=COLOR_BG)

        scroll_content.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scroll_content, anchor="nw")
        
        # Ensure scrollable content resizes horizontally with the main window
        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
            
        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Configure columns inside scrollable container
        scroll_content.columnconfigure(0, weight=1)
        scroll_content.columnconfigure(1, weight=1)

        # Card 1: Score & Gauge (Left Column)
        self.card_gauge = tk.Frame(scroll_content, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                                   highlightthickness=1)
        self.card_gauge.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 15))
        self.card_gauge.columnconfigure(0, weight=1)

        gauge_title = ttk.Label(self.card_gauge, text="AUDIT SCORE & STRENGTH", style="CardTitle.TLabel")
        gauge_title.pack(anchor="w", padx=15, pady=10)

        # Tkinter custom drawing canvas for animated circular meter
        self.gauge_canvas = tk.Canvas(self.card_gauge, width=220, height=220, bg=COLOR_CARD, 
                                      bd=0, highlightthickness=0)
        self.gauge_canvas.pack(pady=5)
        self._draw_empty_gauge()

        # Card 2: Password Metrics (Right Column)
        self.card_metrics = tk.Frame(scroll_content, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                                     highlightthickness=1)
        self.card_metrics.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=(0, 15))
        self.card_metrics.columnconfigure(0, weight=1)
        
        metrics_title = ttk.Label(self.card_metrics, text="CRYPTOGRAPHIC METRICS", style="CardTitle.TLabel")
        metrics_title.grid(row=0, column=0, columnspan=2, sticky="w", padx=15, pady=10)

        self.metrics_labels = {}
        metric_keys = [
            ("Length", "0 characters"),
            ("Shannon Entropy", "0.00 bits"),
            ("Character Pool Size", "0"),
            ("Estimated Combinations", "0"),
            ("Throttled Online Crack Time", "Instant"),
            ("Offline GPU Crack Time", "Instant"),
            ("GPU Cluster Crack Time", "Instant")
        ]
        for idx, (label, val) in enumerate(metric_keys):
            lbl_name = tk.Label(self.card_metrics, text=label, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD, 
                                font=("Segoe UI", 9, "bold"))
            lbl_name.grid(row=idx+1, column=0, sticky="w", padx=15, pady=6)
            
            lbl_val = tk.Label(self.card_metrics, text=val, fg=COLOR_TEXT_MAIN, bg=COLOR_CARD,
                               font=("Consolas", 9, "bold"))
            lbl_val.grid(row=idx+1, column=1, sticky="e", padx=15, pady=6)
            self.metrics_labels[label] = lbl_val

        # Card 3: Checklist (Bottom Left Column)
        self.card_checklist = tk.Frame(scroll_content, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                                       highlightthickness=1)
        self.card_checklist.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(0, 15))
        self.card_checklist.columnconfigure(0, weight=1)

        checklist_title = ttk.Label(self.card_checklist, text="SECURITY CHECKLIST", style="CardTitle.TLabel")
        checklist_title.pack(anchor="w", padx=15, pady=10)

        self.checklist_items = {}
        checklist_keys = [
            ("length", "Minimum 12 characters"),
            ("uppercase", "Contains uppercase letters (A-Z)"),
            ("lowercase", "Contains lowercase letters (a-z)"),
            ("numbers", "Contains numbers (0-9)"),
            ("symbols", "Contains special symbols"),
            ("entropy", "High cryptographic entropy (>60 bits)"),
            ("common", "Not matched in common leaked lists"),
            ("keyboard", "No keyboard pattern sequences"),
            ("repeated", "No repeated character strings")
        ]
        
        for key, text in checklist_keys:
            frame = tk.Frame(self.card_checklist, bg=COLOR_CARD)
            frame.pack(fill="x", padx=15, pady=4)
            
            indicator = tk.Label(frame, text="•", fg=COLOR_TEXT_MUTED, bg=COLOR_CARD, 
                                 font=("Segoe UI", 10, "bold"), width=3)
            indicator.pack(side="left")
            
            lbl = tk.Label(frame, text=text, fg=COLOR_TEXT_MUTED, bg=COLOR_CARD, font=("Segoe UI", 9))
            lbl.pack(side="left", padx=5)
            
            self.checklist_items[key] = (indicator, lbl)

        # Card 4: Recommendations (Bottom Right Column)
        self.card_recs = tk.Frame(scroll_content, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                                  highlightthickness=1)
        self.card_recs.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=(0, 15))
        self.card_recs.columnconfigure(0, weight=1)

        recs_title = ttk.Label(self.card_recs, text="SECURITY RECOMMENDATIONS", style="CardTitle.TLabel")
        recs_title.pack(anchor="w", padx=15, pady=10)

        self.rec_labels_frame = tk.Frame(self.card_recs, bg=COLOR_CARD)
        self.rec_labels_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        
        # Default placeholder text
        self.rec_placeholder = tk.Label(
            self.rec_labels_frame, text="Enter a Wi-Fi password and click 'Analyze' to receive recommendations.",
            fg=COLOR_TEXT_MUTED, bg=COLOR_CARD, font=("Segoe UI", 9, "italic"), wraplength=350, justify="left"
        )
        self.rec_placeholder.pack(anchor="nw", pady=20)

        # --- Report Exporter Row ---
        self.export_panel = tk.Frame(self.frame_auditor, bg=COLOR_BG)
        self.export_panel.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        
        lbl_export = tk.Label(self.export_panel, text="Export Security Report:", fg=COLOR_TEXT_MUTED,
                              bg=COLOR_BG, font=("Segoe UI", 9, "bold"))
        lbl_export.pack(side="left", padx=(0, 15))

        self.btn_export_json = tk.Button(
            self.export_panel, text="JSON Format", bg=COLOR_CARD, fg=COLOR_TEXT_MAIN,
            activebackground=COLOR_CARD_BORDER, activeforeground=COLOR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"), bd=0, padx=15, pady=5, cursor="hand2", state="disabled",
            command=lambda: self._export_report("json")
        )
        self.btn_export_json.pack(side="left", padx=5)

        self.btn_export_txt = tk.Button(
            self.export_panel, text="TXT Dashboard", bg=COLOR_CARD, fg=COLOR_TEXT_MAIN,
            activebackground=COLOR_CARD_BORDER, activeforeground=COLOR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"), bd=0, padx=15, pady=5, cursor="hand2", state="disabled",
            command=lambda: self._export_report("txt")
        )
        self.btn_export_txt.pack(side="left", padx=5)

        self.btn_export_pdf = tk.Button(
            self.export_panel, text="PDF Document", bg=COLOR_CARD, fg=COLOR_TEXT_MAIN,
            activebackground=COLOR_CARD_BORDER, activeforeground=COLOR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"), bd=0, padx=15, pady=5, cursor="hand2", state="disabled",
            command=lambda: self._export_report("pdf")
        )
        self.btn_export_pdf.pack(side="left", padx=5)

    def _draw_empty_gauge(self) -> None:
        """Draws initial placeholder grey arc for the circular strength meter."""
        self.gauge_canvas.delete("all")
        # Base Track Arc (260 degree arc)
        self.gauge_canvas.create_arc(30, 30, 190, 190, start=-220, extent=260, style="arc",
                                     width=14, outline="#1E293B")
        # Center display
        self.gauge_canvas.create_text(110, 95, text="--", fill=COLOR_TEXT_MUTED,
                                      font=("Helvetica", 32, "bold"))
        self.gauge_canvas.create_text(110, 135, text="Awaiting Audit", fill=COLOR_TEXT_MUTED,
                                      font=("Helvetica", 11, "bold"))
        self.gauge_canvas.create_text(110, 165, text="0.00 bits", fill=COLOR_TEXT_MUTED,
                                      font=("Helvetica", 9))

    def _toggle_password_visibility(self) -> None:
        """Toggles masking of characters inside the password entry box."""
        if self.password_visible:
            self.ent_password.configure(show="*")
            self.btn_toggle_visibility.configure(text="👁 Show")
            self.password_visible = False
        else:
            self.ent_password.configure(show="")
            self.btn_toggle_visibility.configure(text="🙈 Hide")
            self.password_visible = True

    def _perform_audit(self) -> None:
        """Starts the password strength audit and kicks off the visual meter animation."""
        pwd = self.ent_password.get()
        if not pwd:
            messagebox.showwarning("Empty Input", "Please enter a Wi-Fi password to perform the security audit.")
            return

        # Perform analysis via analyzer
        results = self.analyzer.analyze(pwd)
        self.last_analysis_results = results
        self.last_password_analyzed = pwd

        # Update metrics table immediately
        self.metrics_labels["Length"].configure(text=f"{len(pwd)} characters")
        self.metrics_labels["Shannon Entropy"].configure(text=f"{results['entropy']} bits")
        self.metrics_labels["Character Pool Size"].configure(text=str(results["pool_size"]))
        self.metrics_labels["Estimated Combinations"].configure(text=f"{results['combinations']:.2e}")
        self.metrics_labels["Throttled Online Crack Time"].configure(text=results["crack_times"]["online"])
        self.metrics_labels["Offline GPU Crack Time"].configure(text=results["crack_times"]["offline_gpu"])
        self.metrics_labels["GPU Cluster Crack Time"].configure(text=results["crack_times"]["gpu_cluster"])

        # Update checklist indicators
        for key, (indicator, lbl) in self.checklist_items.items():
            passed = results["checklist"].get(key, False)
            if passed:
                indicator.configure(text="✔", fg=COLOR_GOOD)
                lbl.configure(fg=COLOR_TEXT_MAIN)
            else:
                indicator.configure(text="✘", fg=COLOR_VERY_WEAK)
                lbl.configure(fg=COLOR_TEXT_MUTED)

        # Update Recommendations list
        for child in self.rec_labels_frame.winfo_children():
            child.destroy()

        if results["recommendations"]:
            for rec in results["recommendations"]:
                lbl_rec = tk.Label(self.rec_labels_frame, text=f"•  {rec}", fg=COLOR_TEXT_MAIN,
                                   bg=COLOR_CARD, font=("Segoe UI", 9), justify="left", 
                                   anchor="nw", wraplength=420)
                lbl_rec.pack(anchor="w", pady=4, fill="x")
        else:
            lbl_success = tk.Label(self.rec_labels_frame, text="✔ Excellent! No critical vulnerabilities found. Ensure WPA3 standard is enabled on your router.",
                                   fg=COLOR_GOOD, bg=COLOR_CARD, font=("Segoe UI", 9, "bold"), 
                                   justify="left", anchor="nw", wraplength=420)
            lbl_success.pack(anchor="w", pady=20)

        # Enable export options
        self.btn_export_json.configure(state="normal", bg=COLOR_CARD_BORDER)
        self.btn_export_txt.configure(state="normal", bg=COLOR_CARD_BORDER)
        self.btn_export_pdf.configure(state="normal", bg=COLOR_CARD_BORDER)

        # Trigger Gauge animation
        if self.anim_timer_id is not None:
            self.root.after_cancel(self.anim_timer_id)
            self.anim_timer_id = None
            
        self.anim_target_score = results["score"]
        self.anim_current_score = 0.0
        self._animate_gauge()

    def _animate_gauge(self) -> None:
        """Increments the circular meter drawing to create a sweeping animation."""
        if self.anim_current_score < self.anim_target_score:
            self.anim_current_score += self.anim_step
            if self.anim_current_score > self.anim_target_score:
                self.anim_current_score = float(self.anim_target_score)
            
            self._redraw_gauge(int(self.anim_current_score))
            self.anim_timer_id = self.root.after(8, self._animate_gauge)
        else:
            # Done animating, ensure final draw matches exact target
            self._redraw_gauge(self.anim_target_score)
            self.anim_timer_id = None

    def _redraw_gauge(self, score: int) -> None:
        """Redraws the canvas gauge at the specified score state."""
        self.gauge_canvas.delete("all")
        
        # Color mapping for rating
        results = self.last_analysis_results
        rating = results["rating"]
        entropy = results["entropy"]

        if score <= 20:
            color = COLOR_VERY_WEAK
            rating_text = "Very Weak"
        elif score <= 40:
            color = COLOR_WEAK
            rating_text = "Weak"
        elif score <= 60:
            color = COLOR_FAIR
            rating_text = "Fair"
        elif score <= 80:
            color = COLOR_GOOD
            rating_text = "Good"
        elif score <= 90:
            color = COLOR_STRONG
            rating_text = "Strong"
        else:
            color = COLOR_EXCELLENT
            rating_text = "Excellent"

        # Background track arc
        self.gauge_canvas.create_arc(30, 30, 190, 190, start=-220, extent=260, style="arc",
                                     width=14, outline="#1E293B")
        
        # Active color-filled arc (extent logic: 260 degrees max corresponding to score 100)
        extent_val = -(score / 100.0) * 260.0
        self.gauge_canvas.create_arc(30, 30, 190, 190, start=220, extent=extent_val, style="arc",
                                     width=14, outline=color)

        # Draw text inside
        self.gauge_canvas.create_text(110, 95, text=f"{score}%", fill=COLOR_TEXT_MAIN,
                                      font=("Helvetica", 32, "bold"))
        self.gauge_canvas.create_text(110, 135, text=rating_text, fill=color,
                                      font=("Helvetica", 12, "bold"))
        self.gauge_canvas.create_text(110, 165, text=f"{entropy:.2f} bits", fill=COLOR_TEXT_MUTED,
                                      font=("Helvetica", 9))

    def _export_report(self, fmt: str) -> None:
        """Saves the current password audit audit results in the user's chosen file format."""
        if not self.last_analysis_results or not self.last_password_analyzed:
            return

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"wifi_audit_{timestamp_str}"

        # Setup reports output directory locally
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        if fmt == "json":
            filepath = filedialog.asksaveasfilename(
                initialdir=reports_dir, initialfile=f"{default_name}.json",
                defaultextension=".json", filetypes=[("JSON files", "*.json")]
            )
            if filepath:
                AuditReporter.export_to_json(self.last_password_analyzed, self.last_analysis_results, filepath)
                messagebox.showinfo("Export Success", f"JSON audit report successfully exported to:\n{filepath}")

        elif fmt == "txt":
            filepath = filedialog.asksaveasfilename(
                initialdir=reports_dir, initialfile=f"{default_name}.txt",
                defaultextension=".txt", filetypes=[("Plain Text files", "*.txt")]
            )
            if filepath:
                AuditReporter.export_to_txt(self.last_password_analyzed, self.last_analysis_results, filepath)
                messagebox.showinfo("Export Success", f"TXT audit report successfully exported to:\n{filepath}")

        elif fmt == "pdf":
            filepath = filedialog.asksaveasfilename(
                initialdir=reports_dir, initialfile=f"{default_name}.pdf",
                defaultextension=".pdf", filetypes=[("PDF Documents", "*.pdf")]
            )
            if filepath:
                # Compile structured data dictionary
                pdf_data = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "score": self.last_analysis_results["score"],
                    "rating": self.last_analysis_results["rating"],
                    "entropy": self.last_analysis_results["entropy"],
                    "pool_size": self.last_analysis_results["pool_size"],
                    "combinations_str": f"{self.last_analysis_results['combinations']:.2e}",
                    "masked_password": AuditReporter._mask_password(self.last_password_analyzed),
                    "length": len(self.last_password_analyzed),
                    "crack_times": self.last_analysis_results["crack_times"],
                    "checklist_items": [
                        ("Minimum 12 characters", self.last_analysis_results["checklist"].get("length", False)),
                        ("Contains uppercase letters (A-Z)", self.last_analysis_results["checklist"].get("uppercase", False)),
                        ("Contains lowercase letters (a-z)", self.last_analysis_results["checklist"].get("lowercase", False)),
                        ("Contains numeric characters (0-9)", self.last_analysis_results["checklist"].get("numbers", False)),
                        ("Contains special symbols", self.last_analysis_results["checklist"].get("symbols", False)),
                        ("High cryptographic entropy (>60 bits)", self.last_analysis_results["checklist"].get("entropy", False)),
                        ("Not matched in common/leaked lists", self.last_analysis_results["checklist"].get("common", False)),
                        ("No simple keyboard sequential runs", self.last_analysis_results["checklist"].get("keyboard", False)),
                        ("No repeated character strings", self.last_analysis_results["checklist"].get("repeated", False))
                    ],
                    "recommendations": self.last_analysis_results["recommendations"]
                }
                AuditReporter.export_to_pdf(self.last_password_analyzed, pdf_data, filepath)
                messagebox.showinfo("Export Success", f"Native PDF audit report successfully exported to:\n{filepath}")

    # =========================================================================
    # GENERATOR VIEW
    # =========================================================================
    def _build_generator_frame(self) -> None:
        """Creates the GUI layout for the cryptographically secure password generator."""
        self.frame_generator = tk.Frame(self.content_container, bg=COLOR_BG)
        self.frame_generator.columnconfigure(0, weight=1)
        self.frame_generator.columnconfigure(1, weight=1)
        self.frame_generator.rowconfigure(1, weight=1)

        # Header Title
        title_label = ttk.Label(self.frame_generator, text="Cryptographic Password Generator", style="Title.TLabel")
        title_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))

        # LEFT COLUMN - Options Panel
        options_panel = tk.Frame(self.frame_generator, bg=COLOR_BG)
        options_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        options_panel.columnconfigure(0, weight=1)

        # Tab Mode Selector inside Generator
        self.gen_mode = tk.StringVar(value="standard")
        
        mode_frame = tk.Frame(options_panel, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER, highlightthickness=1)
        mode_frame.pack(fill="x", pady=(0, 15))
        
        mode_title = ttk.Label(mode_frame, text="GENERATION MODE", style="CardTitle.TLabel")
        mode_title.pack(anchor="w", padx=15, pady=(10, 5))
        
        rad_std = ttk.Radiobutton(mode_frame, text="Random Password (Standard)", variable=self.gen_mode,
                                   value="standard", command=self._toggle_generator_mode)
        rad_std.pack(anchor="w", padx=25, pady=5)
        
        rad_phrase = ttk.Radiobutton(mode_frame, text="Memorable Passphrase (NIST Standard)", variable=self.gen_mode,
                                      value="passphrase", command=self._toggle_generator_mode)
        rad_phrase.pack(anchor="w", padx=25, pady=(5, 15))

        # Standard Options Frame
        self.frame_std_options = tk.Frame(options_panel, bg=COLOR_CARD, bd=1, 
                                          highlightbackground=COLOR_CARD_BORDER, highlightthickness=1)
        self.frame_std_options.pack(fill="x", pady=(0, 15))

        std_title = ttk.Label(self.frame_std_options, text="STANDARD PASSWORD SETTINGS", style="CardTitle.TLabel")
        std_title.pack(anchor="w", padx=15, pady=10)

        # Length Slider
        length_frame = tk.Frame(self.frame_std_options, bg=COLOR_CARD)
        length_frame.pack(fill="x", padx=15, pady=5)
        
        lbl_len = tk.Label(length_frame, text="Password Length:", fg=COLOR_TEXT_MAIN, bg=COLOR_CARD, font=("Segoe UI", 9))
        lbl_len.pack(side="left")
        
        self.lbl_len_val = tk.Label(length_frame, text="16", fg=COLOR_ACCENT, bg=COLOR_CARD, font=("Segoe UI", 10, "bold"))
        self.lbl_len_val.pack(side="right")
        
        self.slider_length = ttk.Scale(self.frame_std_options, from_=8, to=64, value=16, orient="horizontal",
                                       command=self._update_length_label)
        self.slider_length.pack(fill="x", padx=15, pady=(0, 10))

        # Checkbox states
        self.opt_upper = tk.BooleanVar(value=True)
        self.opt_lower = tk.BooleanVar(value=True)
        self.opt_digits = tk.BooleanVar(value=True)
        self.opt_symbols = tk.BooleanVar(value=True)
        self.opt_exclude = tk.BooleanVar(value=False)

        chk_upper = ttk.Checkbutton(self.frame_std_options, text="Include Uppercase Letters (A-Z)", variable=self.opt_upper)
        chk_upper.pack(anchor="w", padx=20, pady=4)
        
        chk_lower = ttk.Checkbutton(self.frame_std_options, text="Include Lowercase Letters (a-z)", variable=self.opt_lower)
        chk_lower.pack(anchor="w", padx=20, pady=4)
        
        chk_digits = ttk.Checkbutton(self.frame_std_options, text="Include Numbers (0-9)", variable=self.opt_digits)
        chk_digits.pack(anchor="w", padx=20, pady=4)
        
        chk_symbols = ttk.Checkbutton(self.frame_std_options, text="Include Special Symbols (!@#$)", variable=self.opt_symbols)
        chk_symbols.pack(anchor="w", padx=20, pady=4)
        
        chk_exclude = ttk.Checkbutton(self.frame_std_options, text="Exclude Ambiguous characters (e.g. 1, l, o, 0)", variable=self.opt_exclude)
        chk_exclude.pack(anchor="w", padx=20, pady=(4, 15))

        # Passphrase Options Frame (initially hidden)
        self.frame_phrase_options = tk.Frame(options_panel, bg=COLOR_CARD, bd=1,
                                             highlightbackground=COLOR_CARD_BORDER, highlightthickness=1)
        # We don't pack it yet

        phrase_title = ttk.Label(self.frame_phrase_options, text="PASSPHRASE SETTINGS", style="CardTitle.TLabel")
        phrase_title.pack(anchor="w", padx=15, pady=10)

        # Word count slider
        words_frame = tk.Frame(self.frame_phrase_options, bg=COLOR_CARD)
        words_frame.pack(fill="x", padx=15, pady=5)
        
        lbl_words = tk.Label(words_frame, text="Number of Words:", fg=COLOR_TEXT_MAIN, bg=COLOR_CARD, font=("Segoe UI", 9))
        lbl_words.pack(side="left")
        
        self.lbl_words_val = tk.Label(words_frame, text="4", fg=COLOR_ACCENT, bg=COLOR_CARD, font=("Segoe UI", 10, "bold"))
        self.lbl_words_val.pack(side="right")
        
        self.slider_words = ttk.Scale(self.frame_phrase_options, from_=3, to=10, value=4, orient="horizontal",
                                      command=self._update_words_label)
        self.slider_words.pack(fill="x", padx=15, pady=(0, 10))

        # Separator choice
        sep_frame = tk.Frame(self.frame_phrase_options, bg=COLOR_CARD)
        sep_frame.pack(fill="x", padx=15, pady=5)
        lbl_sep = tk.Label(sep_frame, text="Separator Symbol:", fg=COLOR_TEXT_MAIN, bg=COLOR_CARD, font=("Segoe UI", 9))
        lbl_sep.pack(side="left")
        
        self.ent_separator = tk.Entry(sep_frame, width=5, bg=COLOR_BG, fg=COLOR_TEXT_MAIN, insertbackground=COLOR_TEXT_MAIN,
                                      bd=0, highlightthickness=1, highlightbackground=COLOR_CARD_BORDER,
                                      font=("Consolas", 10, "bold"), justify="center")
        self.ent_separator.insert(0, "-")
        self.ent_separator.pack(side="right")

        # Capitalize checkbox
        self.opt_capitalize = tk.BooleanVar(value=True)
        chk_cap = ttk.Checkbutton(self.frame_phrase_options, text="Capitalize Each Word", variable=self.opt_capitalize)
        chk_cap.pack(anchor="w", padx=20, pady=(5, 15))


        # RIGHT COLUMN - Output & Action Panel
        output_panel = tk.Frame(self.frame_generator, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                                highlightthickness=1)
        output_panel.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        output_panel.columnconfigure(0, weight=1)

        out_title = ttk.Label(output_panel, text="GENERATED CREDENTIAL", style="CardTitle.TLabel")
        out_title.pack(anchor="w", padx=15, pady=10)

        # Output Display Panel
        display_frame = tk.Frame(output_panel, bg=COLOR_BG, bd=1, highlightbackground=COLOR_CARD_BORDER,
                                 highlightthickness=1)
        display_frame.pack(fill="x", padx=15, pady=10)

        self.lbl_password_out = tk.Label(
            display_frame, textvariable=self.generated_password, fg=COLOR_ACCENT, bg=COLOR_BG,
            font=("Consolas", 14, "bold"), anchor="center", wraplength=320, height=4
        )
        self.lbl_password_out.pack(fill="both", expand=True, padx=10, pady=10)
        self.generated_password.set("Click 'Generate' Below")

        # Copied feedback label
        self.lbl_copy_feedback = tk.Label(output_panel, text="", fg=COLOR_GOOD, bg=COLOR_CARD,
                                          font=("Segoe UI", 9, "bold"))
        self.lbl_copy_feedback.pack(pady=5)

        # Actions Buttons
        btn_generate = tk.Button(
            output_panel, text="Generate Secure Key", bg=COLOR_ACCENT, fg=COLOR_BG,
            activebackground=COLOR_ACCENT_HOVER, activeforeground=COLOR_BG,
            font=("Segoe UI", 10, "bold"), bd=0, padx=25, pady=10, cursor="hand2",
            command=self._generate_credential
        )
        btn_generate.pack(pady=10)

        btn_copy = tk.Button(
            output_panel, text="Copy to Clipboard", bg=COLOR_CARD_BORDER, fg=COLOR_TEXT_MAIN,
            activebackground=COLOR_CARD, activeforeground=COLOR_TEXT_MAIN,
            font=("Segoe UI", 10, "bold"), bd=0, padx=25, pady=10, cursor="hand2",
            command=self._copy_to_clipboard
        )
        btn_copy.pack(pady=10)

        btn_audit_gen = tk.Button(
            output_panel, text="Load into Security Auditor", bg=COLOR_CARD, fg=COLOR_TEXT_MAIN,
            activebackground=COLOR_CARD_BORDER, activeforeground=COLOR_TEXT_MAIN,
            font=("Segoe UI", 9, "bold"), bd=0, padx=20, pady=8, cursor="hand2",
            command=self._send_generated_to_auditor
        )
        btn_audit_gen.pack(pady=(20, 10))

    def _toggle_generator_mode(self) -> None:
        """Swaps standard options and passphrase options frames."""
        mode = self.gen_mode.get()
        if mode == "standard":
            self.frame_phrase_options.pack_forget()
            self.frame_std_options.pack(fill="x", pady=(0, 15))
        else:
            self.frame_std_options.pack_forget()
            self.frame_phrase_options.pack(fill="x", pady=(0, 15))

    def _update_length_label(self, val: str) -> None:
        """Live updater for standard generator length slider label."""
        self.lbl_len_val.configure(text=str(int(float(val))))

    def _update_words_label(self, val: str) -> None:
        """Live updater for passphrase words count slider label."""
        self.lbl_words_val.configure(text=str(int(float(val))))

    def _generate_credential(self) -> None:
        """Triggers the appropriate password generation logic based on the selected mode."""
        mode = self.gen_mode.get()
        self.lbl_copy_feedback.configure(text="")
        
        if mode == "standard":
            length = int(self.slider_length.get())
            pwd = self.generator.generate_secure_password(
                length=length,
                use_upper=self.opt_upper.get(),
                use_lower=self.opt_lower.get(),
                use_digits=self.opt_digits.get(),
                use_symbols=self.opt_symbols.get(),
                exclude_ambiguous=self.opt_exclude.get()
            )
        else:
            words = int(self.slider_words.get())
            sep = self.ent_separator.get()
            pwd = self.generator.generate_passphrase(
                words_count=words,
                separator=sep,
                capitalize=self.opt_capitalize.get()
            )
            
        self.generated_password.set(pwd)

    def _copy_to_clipboard(self) -> None:
        """Copies the generated password to system clipboard."""
        pwd = self.generated_password.get()
        if pwd in ("", "Click 'Generate' Below"):
            return
            
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        self.root.update()
        
        self.lbl_copy_feedback.configure(text="✔ Copied to Clipboard!")
        self.root.after(2000, lambda: self.lbl_copy_feedback.configure(text=""))

    def _send_generated_to_auditor(self) -> None:
        """Sends the generated password directly to the Auditor tab input field."""
        pwd = self.generated_password.get()
        if pwd in ("", "Click 'Generate' Below"):
            return
            
        self.ent_password.delete(0, tk.END)
        self.ent_password.insert(0, pwd)
        self._show_frame("auditor")
        self._perform_audit()

    # =========================================================================
    # ABOUT & SAFETY VIEW
    # =========================================================================
    def _build_about_frame(self) -> None:
        """Creates the Security Notice view frame."""
        self.frame_about = tk.Frame(self.content_container, bg=COLOR_BG)
        self.frame_about.columnconfigure(0, weight=1)

        # Header Title
        title_label = ttk.Label(self.frame_about, text="Security Notice & Disclaimer", style="Title.TLabel")
        title_label.pack(anchor="w", pady=(0, 20))

        # Main Info Card
        info_card = tk.Frame(self.frame_about, bg=COLOR_CARD, bd=1, highlightbackground=COLOR_CARD_BORDER,
                             highlightthickness=1)
        info_card.pack(fill="both", expand=True)

        info_title = tk.Label(info_card, text="IMPORTANT NOTICE FOR USERS & INTERVIEWERS", 
                              fg=COLOR_ACCENT, bg=COLOR_CARD, font=("Segoe UI", 12, "bold"))
        info_title.pack(anchor="w", padx=20, pady=(20, 10))

        terms_text = (
            "This Wi-Fi Password Security Auditor application is built strictly for defensive, educational, "
            "and self-auditing security practices. It serves as a visual evaluator for password complexity "
            "and cryptographic entropy.\n\n"
            "By design and architecture, this tool:\n"
            "• NEVER attempts to capture, crack, or bypass any wireless access points.\n"
            "• NEVER performs active brute-forcing or dictionary attacks over the air.\n"
            "• Runs entirely locally in memory and does not transit wireless credentials over the network.\n\n"
            "Evaluating Password Entropy:\n"
            "Wi-Fi networks rely on WPA2 or WPA3 security handshakes (Pre-Shared Keys or SAE). "
            "Because WPA handshakes can be captured off-the-air by attackers and cracked offline using high-performance "
            "GPU rigs (at billions of combinations per second), the strength of a wireless key is the only defense "
            "against offline dictionary cracking. A minimum length of 12 complex characters, or a 4-word random passphrase "
            "(NIST standard), is highly recommended for security."
        )

        lbl_terms = tk.Label(info_card, text=terms_text, fg=COLOR_TEXT_MAIN, bg=COLOR_CARD, 
                             font=("Segoe UI", 10), justify="left", wraplength=650)
        lbl_terms.pack(anchor="nw", padx=20, pady=10)

        # Standards Logo representation
        standards_frame = tk.Frame(info_card, bg=COLOR_CARD)
        standards_frame.pack(fill="x", padx=20, pady=20)
        
        lbl_standards = tk.Label(
            standards_frame, text="🔒 Compliance & Standards: WPA3 SAE Ready | NIST Special Publication 800-63B",
            fg=COLOR_TEXT_MUTED, bg=COLOR_CARD, font=("Segoe UI", 9, "bold")
        )
        lbl_standards.pack(anchor="w")

if __name__ == "__main__":
    # Prevent scaling issues on high-DPI displays on Windows
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    root = tk.Tk()
    app = WiFiSecurityAuditorApp(root)
    root.mainloop()
