#!/usr/bin/env python3
"""Desktop window that opens a DMARC attachment and shows analysis as plain text."""

import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk
from tkinter.scrolledtext import ScrolledText

from dmarc_analyzer import analyze_viewer_path

REPORT_FILETYPES = [
    ("DMARC reports", "*.xml *.gz *.zip *.eml"),
    ("XML", "*.xml"),
    ("Gzip", "*.gz"),
    ("Zip", "*.zip"),
    ("Email", "*.eml"),
    ("All files", "*.*"),
]


def _app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _repo_root() -> str:
    """Directory that contains src/, config/, and dist/ during development."""
    return os.path.dirname(_app_dir())


def _bundled_example_path() -> str:
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", _app_dir())
        return os.path.join(base, "analyzer.env.example")
    return os.path.join(_repo_root(), "config", "analyzer.env.example")


def resolve_env_path() -> str:
    explicit = os.environ.get("DMARC_ANALYZER_ENV", "").strip()
    if explicit:
        return explicit
    if getattr(sys, "frozen", False):
        return os.path.join(_app_dir(), "analyzer.env")
    for path in (
        os.path.join(os.getcwd(), "analyzer.env"),
        os.path.join(_repo_root(), "dist", "analyzer.env"),
        os.path.join(_repo_root(), "analyzer.env"),
    ):
        if os.path.isfile(path):
            return path
    return os.path.join(_repo_root(), "dist", "analyzer.env")


def ensure_env_file() -> str:
    """Return the viewer env file, creating it from the example if needed."""
    path = resolve_env_path()
    if os.path.isfile(path):
        return path
    example = _bundled_example_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.isfile(example):
        shutil.copyfile(example, path)
    else:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "TARGET_DOMAINS=example.com,4job.co\n"
                "AUTHORIZED_SERVER_NETS=95.217.200.86/32,120.138.18.240/28,127.0.0.1/32\n"
                "FALLBACK_DKIM_SELECTORS=default,s1,srs,mail\n"
                "ALERT_EMAIL_TO=postmaster@example.com\n"
                "ALERT_EMAIL_FROM=dmarc-analyzer@example.com\n"
                "DISPATCH_METHOD=smtp\n"
                "SMTP_HOST=127.0.0.1\n"
                "SMTP_PORT=25\n"
            )
    return path


class DmarcViewer(tk.Tk):
    def __init__(self, initial_path=None):
        super().__init__()
        self.title("DMARC Analyzer")
        self.geometry("800x600")
        self.minsize(640, 400)
        self.env_path = ensure_env_file()

        bar = ttk.Frame(self, padding=(8, 8, 8, 0))
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="Open", command=self.open_dialog).pack(side=tk.LEFT)
        ttk.Button(bar, text="Config", command=self.open_config).pack(side=tk.LEFT, padx=(8, 0))
        self.filename_var = tk.StringVar(value="No file open")
        ttk.Label(bar, textvariable=self.filename_var).pack(side=tk.LEFT, padx=8)

        self.text = ScrolledText(
            self,
            wrap=tk.WORD,
            font=("TkFixedFont", 10),
            state=tk.DISABLED,
        )
        self.text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        if initial_path:
            self.load_path(initial_path)

    def set_text(self, content: str) -> None:
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", content)
        self.text.configure(state=tk.DISABLED)

    def open_dialog(self) -> None:
        path = filedialog.askopenfilename(title="Open DMARC report", filetypes=REPORT_FILETYPES)
        if path:
            self.load_path(path)

    def open_config(self) -> None:
        path = ensure_env_file()
        self.env_path = path
        try:
            subprocess.Popen(["xdg-open", path], start_new_session=True)
        except OSError as exc:
            self.set_text(f"Could not open config file {path}: {exc}")

    def load_path(self, path: str) -> None:
        self.filename_var.set(os.path.basename(path))
        self.env_path = ensure_env_file()
        self.set_text("Analyzing...")
        thread = threading.Thread(target=self._analyze, args=(path, self.env_path), daemon=True)
        thread.start()

    def _analyze(self, path: str, env_path: str) -> None:
        try:
            result = analyze_viewer_path(path, env_path=env_path)
        except Exception as exc:
            result = f"Could not analyze file: {exc}"
        self.after(0, lambda text=result: self.set_text(text))


def main() -> None:
    ensure_env_file()
    initial_path = sys.argv[1] if len(sys.argv) > 1 else None
    app = DmarcViewer(initial_path)
    app.mainloop()


if __name__ == "__main__":
    main()
