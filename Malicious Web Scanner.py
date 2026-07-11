import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import csv
import os
import sys
import threading
import queue
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

REPORT_FILE = "reports/report.csv"
# ---------------- THEME ---------------- #
# Centralized so colors/fonts are consistent everywhere and easy to swap
# (e.g. for a future light-mode toggle).

THEME = {
    "bg": "#1a1a1a",
    "bg_panel": "#242424",
    "fg": "#eaeaea",
    "accent": "#ff3333",
    "accent_dark": "#cc2929",
    "safe": "#33cc66",
    "malicious": "#ff3333",
    "error": "#ffb020",
    "entry_bg": "#2e2e2e",
    "entry_fg": "#ffffff",
    "font_title": ("Segoe UI", 20, "bold"),
    "font_heading": ("Segoe UI", 12, "bold"),
    "font_body": ("Segoe UI", 10),
    "font_mono": ("Consolas", 10),
}

# ---------------- APPLICATION ---------------- #


class MalwareSlayer(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Malware Slayer")
        self.geometry("720x680")
        self.minsize(620, 560)
        self.configure(bg=THEME["bg"])

        os.makedirs("reports", exist_ok=True)

        self.result_queue = queue.Queue()
        self.scan_total = 0
        self.scan_done = 0

        self._setup_style()
        self._check_api_key()
        self.create_widgets()
        self.load_history()

        self.after(150, self._poll_queue)

    # ---------------- Setup ---------------- #

    def _setup_style(self):
        style = ttk.Style(self)
        # 'clam' is the most themeable built-in ttk theme
        style.theme_use("clam")

        style.configure(
            "TFrame", background=THEME["bg"]
        )
        style.configure(
            "Panel.TFrame", background=THEME["bg_panel"]
        )
        style.configure(
            "TLabel", background=THEME["bg"], foreground=THEME["fg"], font=THEME["font_body"]
        )
        style.configure(
            "Heading.TLabel", background=THEME["bg"], foreground=THEME["fg"], font=THEME["font_heading"]
        )
        style.configure(
            "Status.TLabel", background=THEME["bg"], foreground=THEME["fg"], font=THEME["font_heading"]
        )
        style.configure(
            "TEntry",
            fieldbackground=THEME["entry_bg"],
            foreground=THEME["entry_fg"],
            insertcolor=THEME["entry_fg"],
            borderwidth=1,
        )
        style.configure(
            "Accent.TButton",
            background=THEME["accent"],
            foreground="white",
            font=THEME["font_heading"],
            padding=8,
            borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", THEME["accent_dark"])])

        style.configure(
            "Secondary.TButton",
            background="#2f5fa8",
            foreground="white",
            font=THEME["font_heading"],
            padding=8,
            borderwidth=0,
        )
        style.map("Secondary.TButton", background=[("active", "#254a85")])

        style.configure(
            "TProgressbar",
            troughcolor=THEME["bg_panel"],
            background=THEME["accent"],
            thickness=14,
        )

        # Treeview (scan history table)
        style.configure(
            "Treeview",
            background=THEME["entry_bg"],
            fieldbackground=THEME["entry_bg"],
            foreground=THEME["fg"],
            rowheight=26,
            font=THEME["font_mono"],
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=THEME["bg_panel"],
            foreground=THEME["fg"],
            font=THEME["font_heading"],
            borderwidth=0,
        )
        style.map("Treeview", background=[("selected", "#3a3a3a")])

    def _check_api_key(self):
        if not API_KEY:
            messagebox.showwarning(
                "API Key Missing",
                "No VirusTotal API key found in the VT_API_KEY environment variable.\n\n"
                "Scans will fail until it's set. See the comment at the top of this "
                "script for instructions.",
            )

    # ---------------- GUI ---------------- #

    def create_widgets(self):

        # Header
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill=tk.X, padx=20, pady=(20, 10))

        title_row = ttk.Frame(header, style="TFrame")
        title_row.pack(fill=tk.X)

        tk.Label(
            title_row,
            text="\U0001F6E1",  # shield emoji as a lightweight icon stand-in
            font=("Segoe UI Emoji", 22),
            bg=THEME["bg"],
            fg=THEME["accent"],
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(title_row, text="Malware Slayer", style="TLabel", font=THEME["font_title"]).pack(
            side=tk.LEFT
        )

        ttk.Label(
            header,
            text="Scan URLs against VirusTotal for known threats",
            style="TLabel",
            foreground="#999999",
        ).pack(anchor="w", pady=(2, 0))

        # Input panel
        input_panel = ttk.Frame(self, style="Panel.TFrame")
        input_panel.pack(fill=tk.X, padx=20, pady=10)

        inner = ttk.Frame(input_panel, style="Panel.TFrame")
        inner.pack(fill=tk.X, padx=16, pady=16)

        ttk.Label(inner, text="Website URL", style="Heading.TLabel", background=THEME["bg_panel"]).pack(
            anchor="w"
        )

        entry_row = ttk.Frame(inner, style="Panel.TFrame")
        entry_row.pack(fill=tk.X, pady=(6, 12))

        self.url_entry = ttk.Entry(entry_row, font=THEME["font_body"])
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
        self.url_entry.bind("<Return>", lambda e: self.scan_url())

        button_row = ttk.Frame(inner, style="Panel.TFrame")
        button_row.pack(fill=tk.X)

        self.scan_btn = ttk.Button(
            button_row, text="Scan URL", style="Accent.TButton", command=self.scan_url
        )
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.bulk_btn = ttk.Button(
            button_row, text="Bulk Scan\u2026", style="Secondary.TButton", command=self.bulk_scan
        )
        self.bulk_btn.pack(side=tk.LEFT)

        # Status + progress
        status_panel = ttk.Frame(self, style="TFrame")
        status_panel.pack(fill=tk.X, padx=20, pady=(0, 10))

        self.status = ttk.Label(status_panel, text="Status: Ready", style="Status.TLabel")
        self.status.pack(anchor="w")

        self.progress = ttk.Progressbar(
            status_panel, style="TProgressbar", mode="determinate", maximum=100
        )
        self.progress.pack(fill=tk.X, pady=(6, 0))
        self.progress["value"] = 0

        # History table
        history_panel = ttk.Frame(self, style="TFrame")
        history_panel.pack(fill=tk.BOTH, expand=True, padx=20, pady=(10, 20))

        ttk.Label(history_panel, text="Scan History", style="Heading.TLabel").pack(anchor="w")

        table_frame = ttk.Frame(history_panel, style="TFrame")
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        columns = ("time", "url", "status")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", style="Treeview"
        )
        self.tree.heading("time", text="Time")
        self.tree.heading("url", text="URL")
        self.tree.heading("status", text="Status")
        self.tree.column("time", width=140, anchor="w")
        self.tree.column("url", width=320, anchor="w")
        self.tree.column("status", width=110, anchor="center")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Row color tags
        self.tree.tag_configure("safe", foreground=THEME["safe"])
        self.tree.tag_configure("malicious", foreground=THEME["malicious"])
        self.tree.tag_configure("error", foreground=THEME["error"])

    # ---------------- VirusTotal ---------------- #

    def check_url(self, url):
        """Check a single URL using VirusTotal API. Runs on a background thread."""
        if not API_KEY:
            return "Error: No API key set"

        params = {"apikey": API_KEY, "resource": url}

        try:
            response = requests.get(
                "https://www.virustotal.com/vtapi/v2/url/report",
                params=params,
                timeout=10,
            )
            response.raise_for_status()
            result = response.json()

            if result.get("response_code") == 1:
                if result["positives"] > 0:
                    return "MALICIOUS"
                else:
                    return "SAFE"

            return "No report found"

        except requests.exceptions.RequestException as e:
            return f"Error: {e}"

    # ---------------- Single Scan ---------------- #

    def scan_url(self):
        url = self.url_entry.get().strip()

        if url == "":
            messagebox.showwarning("Warning", "Enter a URL")
            return

        self._set_busy(True)
        self.status.config(text="Status: Scanning\u2026")
        self.progress.config(mode="indeterminate")
        self.progress.start(12)

        def worker():
            result = self.check_url(url)
            self.result_queue.put(("single", url, result))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------- Bulk Scan ---------------- #

    def bulk_scan(self):
        file = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv")]
        )
        if not file:
            return

        with open(file, "r") as f:
            urls = [u.strip() for u in f.read().splitlines() if u.strip()]

        if not urls:
            messagebox.showinfo("Bulk Scan", "No URLs found in that file.")
            return

        self._set_busy(True)
        self.scan_total = len(urls)
        self.scan_done = 0
        self.progress.config(mode="determinate", maximum=self.scan_total, value=0)
        self.status.config(text=f"Status: Scanning 0/{self.scan_total}\u2026")

        def worker():
            for url in urls:
                result = self.check_url(url)
                self.result_queue.put(("bulk_item", url, result))
            self.result_queue.put(("bulk_done", None, None))

        threading.Thread(target=worker, daemon=True).start()

    # ---------------- Thread-safe UI updates ---------------- #

    def _poll_queue(self):
        try:
            while True:
                kind, url, result = self.result_queue.get_nowait()

                if kind == "single":
                    self.progress.stop()
                    self.progress.config(mode="determinate", value=0)
                    self.status.config(text=f"Status: {result}")
                    self.save_result(url, result)
                    self.load_history()
                    self._set_busy(False)

                    if result == "SAFE":
                        messagebox.showinfo("Result", f"{url}\n\nSAFE")
                    elif result == "MALICIOUS":
                        messagebox.showwarning("Result", f"{url}\n\nMALICIOUS")
                    else:
                        messagebox.showerror("Result", result)

                elif kind == "bulk_item":
                    self.save_result(url, result)
                    self.scan_done += 1
                    self.progress["value"] = self.scan_done
                    self.status.config(
                        text=f"Status: Scanning {self.scan_done}/{self.scan_total}\u2026"
                    )

                elif kind == "bulk_done":
                    self.load_history()
                    self.status.config(text="Status: Ready")
                    self._set_busy(False)
                    messagebox.showinfo("Completed", "Bulk Scan Finished")

        except queue.Empty:
            pass

        self.after(150, self._poll_queue)

    def _set_busy(self, busy):
        state = "disabled" if busy else "!disabled"
        self.scan_btn.state([state] if busy else ["!disabled"])
        self.bulk_btn.state([state] if busy else ["!disabled"])

    # ---------------- Save ---------------- #

    def save_result(self, url, status):
        file_exists = os.path.exists(REPORT_FILE)

        with open(REPORT_FILE, "a", newline="") as f:
            writer = csv.writer(f)

            if not file_exists:
                writer.writerow(["Time", "URL", "Status"])

            writer.writerow(
                [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url, status]
            )

    # ---------------- History ---------------- #

    def load_history(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        if not os.path.exists(REPORT_FILE):
            return

        with open(REPORT_FILE, "r") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            rows = list(reader)

        # newest first
        for row in reversed(rows):
            if len(row) < 3:
                continue
            time_str, url, status = row[0], row[1], row[2]

            if status == "SAFE":
                tag = "safe"
            elif status == "MALICIOUS":
                tag = "malicious"
            else:
                tag = "error"

            self.tree.insert("", tk.END, values=(time_str, url, status), tags=(tag,))


# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    app = MalwareSlayer()
    app.mainloop()