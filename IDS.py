import tkinter as tk
from tkinter import ttk
from datetime import datetime


# ── Dark theme palette ──────────────────────────────
BG_MAIN = "#0f111a"
BG_PANEL = "#161925"
FG_TEXT = "#e6e6e6"
FG_HEADER = "#ffffff"

SEVERITY_COLORS = {
    "INFO": "#9aa5ce",
    "LOW": "#7dcfff",
    "MEDIUM": "#ff9e64",
    "HIGH": "#f7768e",
    "CRITICAL": "#ff007c",
}


class IDPSGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IDPS Dashboard")
        self.root.geometry("1000x650")
        self.root.configure(bg=BG_MAIN)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_layout()

    # ──────────────────────────────────────────────
    # Layout
    # ──────────────────────────────────────────────
    def _build_layout(self):
        header = tk.Label(
            self.root,
            text="Intrusion Detection & Prevention System",
            bg=BG_MAIN,
            fg=FG_HEADER,
            font=("Segoe UI", 18, "bold")
        )
        header.pack(pady=15)

        container = tk.Frame(self.root, bg=BG_MAIN)
        container.pack(fill="both", expand=True, padx=12, pady=12)

        container.columnconfigure((0, 1), weight=1)
        container.rowconfigure((0, 1), weight=1)

        self.panels = {
            "ARP": self._create_panel(container, "ARP Spoofing", 0, 0),
            "DNS": self._create_panel(container, "DNS Spoofing", 0, 1),
            "MITM": self._create_panel(container, "MITM", 1, 0),
            "PORT": self._create_panel(container, "Port Scanning", 1, 1),
        }

    def _create_panel(self, parent, title, row, col):
        frame = tk.LabelFrame(
            parent,
            text=title,
            bg=BG_PANEL,
            fg=FG_TEXT,
            font=("Segoe UI", 11, "bold"),
            bd=2,
            relief="groove"
        )
        frame.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)

        text = tk.Text(
            frame,
            bg=BG_PANEL,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            wrap="word",
            state="disabled",
            font=("Consolas", 10),
            relief="flat"
        )

        scrollbar = tk.Scrollbar(
            frame,
            command=text.yview,
            bg=BG_PANEL,
            troughcolor=BG_MAIN,
            activebackground=BG_MAIN
        )

        text.configure(yscrollcommand=scrollbar.set)

        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Severity color tags
        for sev, color in SEVERITY_COLORS.items():
            text.tag_config(sev, foreground=color)

        return text

    # ──────────────────────────────────────────────
    # Public API (thread-safe)
    # ──────────────────────────────────────────────
    def add_alert(self, category: str, message: str, severity="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        severity = severity.upper()

        def _update():
            if category not in self.panels:
                return

            panel = self.panels[category]
            panel.configure(state="normal")

            panel.insert(
                "end",
                f"[{timestamp}] [{severity}] {message}\n",
                severity
            )

            panel.configure(state="disabled")
            panel.see("end")

        self.root.after(0, _update)

    # ──────────────────────────────────────────────
    def on_close(self):
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ──────────────────────────────────────────────
# Standalone test
# ──────────────────────────────────────────────
if __name__ == "__main__":
    gui = IDPSGui()

    gui.add_alert("ARP", "Gateway MAC mismatch detected", "HIGH")
    gui.add_alert("DNS", "Suspicious DNS resolver response", "MEDIUM")
    gui.add_alert("PORT", "Port scan from 192.168.1.10", "LOW")
    gui.add_alert("MITM", "MITM correlation confirmed", "CRITICAL")

    gui.run()