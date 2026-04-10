import io
import os
import queue
import threading

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from config import Config
from data_tools.data_loader import sync_signatures
from data_tools.db_setup import setup_db
from gui.components.history_panel import HistoryPanel
from gui.components.log_panel import LogPanel
from gui.components.results_panel import ResultsPanel
from malware_scanner.reporting import write_report
from malware_scanner.scanner import ScanStore, ScannerEngine


ROOT_DIR = Path(__file__).resolve().parent.parent
JSON_OUTPUT = ROOT_DIR / "data" / "malware_signatures.json"


class QueueWriter(io.TextIOBase):
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue

    def write(self, text: str) -> int:
        cleaned = text.strip()
        if cleaned:
            self.event_queue.put({"type": "log", "level": "INFO", "message": cleaned})
        return len(text)

    def flush(self) -> None:
        return


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Hybrid Malware Scanner")
        self.geometry("1440x860")
        self.minsize(1180, 760)

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self._configure_ttk_style()

        self.event_queue: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.scan_thread: threading.Thread | None = None
        self.boot_thread: threading.Thread | None = None
        self.history_thread: threading.Thread | None = None
        self.current_scanner: ScannerEngine | None = None

        self.current_state = "idle"
        self.last_scan_started_at: datetime | None = None
        self.last_report_path: str | None = None
        self.is_fullscreen = False

        self.path_var = ctk.StringVar(value="")
        self.state_var = ctk.StringVar(value="IDLE")
        self.progress_text_var = ctk.StringVar(value="Ready")

        self.total_var = ctk.StringVar(value="0")
        self.hash_var = ctk.StringVar(value="0")
        self.yara_var = ctk.StringVar(value="0")
        self.clean_var = ctk.StringVar(value="0")
        self.err_var = ctk.StringVar(value="0")
        self.elapsed_var = ctk.StringVar(value="0.00s")

        self._build_layout()
        self._bind_shortcuts()
        self._set_state("idle")
        self._refresh_history()
        self.after(100, self._drain_events)

    def _configure_ttk_style(self) -> None:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(
            "Treeview",
            rowheight=28,
            font=("Segoe UI", 10),
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground="#0f172a",
            bordercolor="#e2e8f0",
        )
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI Semibold", 10),
            background="#f8fafc",
            foreground="#0f172a",
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#dbeafe")],
            foreground=[("selected", "#0f172a")],
        )

    def _bind_shortcuts(self) -> None:
        self.bind("<F11>", lambda _event: self._toggle_fullscreen())
        self.bind("<Escape>", lambda _event: self._exit_fullscreen())

    def _build_layout(self) -> None:
        self.configure(fg_color="#f3f6fb")

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_header()
        self._build_metrics()
        self._build_workspace()
        self._build_footer()

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=16)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        header.grid_columnconfigure(1, weight=1)

        identity = ctk.CTkFrame(header, fg_color="transparent")
        identity.grid(row=0, column=0, sticky="w", padx=(14, 8), pady=12)
        ctk.CTkLabel(
            identity,
            text="Hybrid Malware Scanner",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=24, weight="bold"),
            text_color="#0f172a",
        ).pack(anchor="w")
        ctk.CTkLabel(
            identity,
            text="CustomTkinter Dashboard - real-time YARA + Hashing workflow",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color="#475569",
        ).pack(anchor="w", pady=(2, 0))

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, sticky="ew", padx=(8, 12), pady=12)
        controls.grid_columnconfigure(0, weight=1)

        self.path_entry = ctk.CTkEntry(
            controls,
            textvariable=self.path_var,
            height=38,
            corner_radius=12,
            placeholder_text="Chon file hoac folder can quet...",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        )
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.file_btn = ctk.CTkButton(
            controls,
            text="File",
            width=74,
            height=38,
            corner_radius=12,
            command=self._pick_file,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.file_btn.grid(row=0, column=1, padx=4)

        self.folder_btn = ctk.CTkButton(
            controls,
            text="Folder",
            width=84,
            height=38,
            corner_radius=12,
            command=self._pick_folder,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.folder_btn.grid(row=0, column=2, padx=4)

        self.start_btn = ctk.CTkButton(
            controls,
            text="Quet",
            width=86,
            height=38,
            corner_radius=12,
            fg_color="#0f766e",
            hover_color="#115e59",
            command=self._start_scan,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.start_btn.grid(row=0, column=3, padx=4)

        self.cancel_btn = ctk.CTkButton(
            controls,
            text="Dung",
            width=86,
            height=38,
            corner_radius=12,
            fg_color="#b91c1c",
            hover_color="#991b1b",
            command=self._cancel_scan,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.cancel_btn.grid(row=0, column=4, padx=4)

        self.boot_btn = ctk.CTkButton(
            controls,
            text="Sync Data",
            width=98,
            height=38,
            corner_radius=12,
            command=self._start_boot,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.boot_btn.grid(row=0, column=5, padx=4)

        self.report_btn = ctk.CTkButton(
            controls,
            text="Bao cao",
            width=94,
            height=38,
            corner_radius=12,
            command=self._open_report,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.report_btn.grid(row=0, column=6, padx=4)

        self.fullscreen_btn = ctk.CTkButton(
            controls,
            text="Toan man hinh",
            width=122,
            height=38,
            corner_radius=12,
            fg_color="#334155",
            hover_color="#1e293b",
            command=self._toggle_fullscreen,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.fullscreen_btn.grid(row=0, column=7, padx=(4, 0))

    def _build_metrics(self) -> None:
        metrics = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=16)
        metrics.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))

        for col in range(6):
            metrics.grid_columnconfigure(col, weight=1)

        self._metric_card(metrics, 0, "Tong file", self.total_var, "#2563eb")
        self._metric_card(metrics, 1, "Hash hit", self.hash_var, "#dc2626")
        self._metric_card(metrics, 2, "YARA hit", self.yara_var, "#ea580c")
        self._metric_card(metrics, 3, "Clean", self.clean_var, "#0f766e")
        self._metric_card(metrics, 4, "Errors", self.err_var, "#b91c1c")
        self._metric_card(metrics, 5, "Elapsed", self.elapsed_var, "#4f46e5")

    def _metric_card(self, parent, col: int, title: str, value_var: ctk.StringVar, accent: str) -> None:
        card = ctk.CTkFrame(parent, fg_color="#f8fafc", corner_radius=14)
        card.grid(row=0, column=col, sticky="ew", padx=8, pady=10)
        ctk.CTkLabel(
            card,
            text=title,
            text_color="#64748b",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        ).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            card,
            textvariable=value_var,
            text_color=accent,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=26, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(0, 10))

    def _build_workspace(self) -> None:
        workspace = ctk.CTkFrame(self, fg_color="transparent")
        workspace.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 8))
        workspace.grid_rowconfigure(0, weight=1)
        workspace.grid_columnconfigure(0, weight=3)
        workspace.grid_columnconfigure(1, weight=2)

        self.results_panel = ResultsPanel(workspace, fg_color="#ffffff", corner_radius=16)
        self.results_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        right_col = ctk.CTkFrame(workspace, fg_color="transparent")
        right_col.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right_col.grid_rowconfigure(0, weight=1)
        right_col.grid_rowconfigure(1, weight=1)
        right_col.grid_columnconfigure(0, weight=1)

        self.history_panel = HistoryPanel(right_col, fg_color="#ffffff", corner_radius=16)
        self.history_panel.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        self.history_panel.set_refresh_handler(self._refresh_history)

        self.log_panel = LogPanel(right_col, fg_color="#ffffff", corner_radius=16)
        self.log_panel.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=16)
        footer.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 14))
        footer.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(footer, progress_color="#0f766e")
        self.progress.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))
        self.progress.set(0)

        info_row = ctk.CTkFrame(footer, fg_color="transparent")
        info_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
        info_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            info_row,
            textvariable=self.progress_text_var,
            text_color="#334155",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            info_row,
            text="State:",
            text_color="#64748b",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        ).grid(row=0, column=1, sticky="e", padx=(0, 6))

        ctk.CTkLabel(
            info_row,
            textvariable=self.state_var,
            text_color="#0f172a",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        ).grid(row=0, column=2, sticky="e")

    def _toggle_fullscreen(self) -> None:
        self.is_fullscreen = not self.is_fullscreen
        self.attributes("-fullscreen", self.is_fullscreen)
        self.fullscreen_btn.configure(text="Thu nho" if self.is_fullscreen else "Toan man hinh")

    def _exit_fullscreen(self) -> None:
        if not self.is_fullscreen:
            return
        self.is_fullscreen = False
        self.attributes("-fullscreen", False)
        self.fullscreen_btn.configure(text="Toan man hinh")

    def _set_state(self, state: str) -> None:
        self.current_state = state
        self.state_var.set(state.upper())

        if state == "idle":
            self.file_btn.configure(state="normal")
            self.folder_btn.configure(state="normal")
            self.start_btn.configure(state="normal")
            self.boot_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.report_btn.configure(state="normal" if self.last_report_path else "disabled")
            return

        if state == "scanning":
            self.file_btn.configure(state="disabled")
            self.folder_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.boot_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
            self.report_btn.configure(state="disabled")
            return

        if state == "canceling":
            self.file_btn.configure(state="disabled")
            self.folder_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.boot_btn.configure(state="disabled")
            self.cancel_btn.configure(state="disabled")
            self.report_btn.configure(state="disabled")
            return

        if state == "booting":
            self.file_btn.configure(state="disabled")
            self.folder_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.boot_btn.configure(state="disabled")
            self.cancel_btn.configure(state="disabled")
            self.report_btn.configure(state="normal" if self.last_report_path else "disabled")
            return

        if state in {"completed", "error"}:
            self.file_btn.configure(state="normal")
            self.folder_btn.configure(state="normal")
            self.start_btn.configure(state="normal")
            self.boot_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.report_btn.configure(state="normal" if self.last_report_path else "disabled")
            return

        self._set_state("idle")

    def _pick_file(self) -> None:
        file_path = filedialog.askopenfilename(title="Select file to scan")
        if file_path:
            self.path_var.set(file_path)

    def _pick_folder(self) -> None:
        folder_path = filedialog.askdirectory(title="Select folder to scan")
        if folder_path:
            self.path_var.set(folder_path)

    def _start_boot(self) -> None:
        if self.boot_thread and self.boot_thread.is_alive():
            return

        self._set_state("booting")
        self.progress_text_var.set("Dang dong bo du lieu signatures...")
        self.boot_thread = threading.Thread(target=self._run_boot_worker, daemon=True)
        self.boot_thread.start()

    def _run_boot_worker(self) -> None:
        writer = QueueWriter(self.event_queue)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                JSON_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
                setup_db()
                sync_signatures(JSON_OUTPUT)
            self.event_queue.put({"type": "boot_done", "exit_code": 0})
        except Exception as exc:
            self.event_queue.put({"type": "boot_done", "exit_code": 1, "message": str(exc)})

    def _start_scan(self) -> None:
        if self.current_state in {"scanning", "canceling", "booting"}:
            return
        if self.scan_thread and self.scan_thread.is_alive():
            return

        raw_path = self.path_var.get().strip().strip('"\'')
        if not raw_path:
            messagebox.showerror("Missing target", "Please choose a file or folder to scan.")
            return

        target = Path(raw_path).expanduser().resolve()
        if not target.exists():
            messagebox.showerror("Invalid path", f"Target does not exist:\n{target}")
            return

        self._reset_metrics()
        self.results_panel.clear()
        self.cancel_event.clear()
        self.last_scan_started_at = datetime.now()
        self.last_report_path = None
        self._set_state("scanning")
        self.progress_text_var.set(f"Dang quet: {target}")

        self.scan_thread = threading.Thread(target=self._run_scan_worker, args=(str(target),), daemon=True)
        self.scan_thread.start()

    def _run_scan_worker(self, target_path: str) -> None:
        scanner: ScannerEngine | None = None
        start = datetime.now()

        try:
            scanner = ScannerEngine(
                rules_path=Config.YARA_RULES_PATH,
                log_callback=self._on_scanner_log,
                result_callback=self._on_scanner_result,
                cancel_event=self.cancel_event,
            )
            self.current_scanner = scanner

            target = Path(target_path)
            if target.is_file():
                scanner.scan(target_path)
                duration = (datetime.now() - start).total_seconds()
                metrics = dict(scanner.metrics)
            else:
                metrics, duration = scanner.scan_directory(target_path)

            report_path = write_report(scanner.store, start)
            self.event_queue.put(
                {
                    "type": "scan_done",
                    "cancelled": self.cancel_event.is_set(),
                    "metrics": metrics,
                    "duration": duration,
                    "report_path": report_path,
                }
            )
        except Exception as exc:
            self.event_queue.put({"type": "scan_failed", "message": str(exc)})
        finally:
            if scanner:
                scanner.close()
            self.current_scanner = None

    def _on_scanner_log(self, payload: dict) -> None:
        self.event_queue.put(payload)

    def _on_scanner_result(self, payload: dict) -> None:
        self.event_queue.put(payload)

    def _cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self._set_state("canceling")
            self.progress_text_var.set("Da yeu cau dung quet. Dang doi worker ket thuc...")

    def _open_report(self) -> None:
        if not self.last_report_path:
            return

        report_path = Path(self.last_report_path)
        if not report_path.exists():
            messagebox.showerror("Report missing", f"Report file not found:\n{report_path}")
            return

        try:
            if os.name == "nt":
                os.startfile(report_path)  # type: ignore[attr-defined]
            else:
                os.system(f'xdg-open "{report_path}"')
        except Exception as exc:
            messagebox.showerror("Open report error", str(exc))

    def _refresh_history(self) -> None:
        if self.history_thread and self.history_thread.is_alive():
            return

        self.history_thread = threading.Thread(target=self._run_history_worker, daemon=True)
        self.history_thread.start()

    def _run_history_worker(self) -> None:
        store = ScanStore()
        try:
            rows = store.fetch_recent_history(limit=300)
            self.event_queue.put({"type": "history_rows", "rows": rows})
        except Exception as exc:
            self.event_queue.put({"type": "history_error", "message": str(exc)})
        finally:
            store.close()

    def _reset_metrics(self) -> None:
        self.total_var.set("0")
        self.hash_var.set("0")
        self.yara_var.set("0")
        self.clean_var.set("0")
        self.err_var.set("0")
        self.elapsed_var.set("0.00s")
        self.progress.set(0)

    def _update_metrics(self, metrics: dict[str, int]) -> None:
        total = int(metrics.get("total", 0) or 0)
        hash_count = int(metrics.get("hash", 0) or 0)
        yara_count = int(metrics.get("yara", 0) or 0)
        clean_count = int(metrics.get("clean", 0) or 0)
        err_count = int(metrics.get("err", 0) or 0)

        self.total_var.set(str(total))
        self.hash_var.set(str(hash_count))
        self.yara_var.set(str(yara_count))
        self.clean_var.set(str(clean_count))
        self.err_var.set(str(err_count))

        processed = hash_count + yara_count + clean_count + err_count
        progress = (processed / total) if total > 0 else 0.0
        self.progress.set(max(0.0, min(1.0, progress)))
        self.progress_text_var.set(f"Processed {processed}/{total} files")

    def _drain_events(self) -> None:
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break

            event_type = event.get("type")
            if event_type == "log":
                level = str(event.get("level", "INFO")).upper()
                message = str(event.get("message", "")).strip()
                if message:
                    self.log_panel.append(f"[{level}] {message}\n")
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_metrics(metrics)

            elif event_type == "result":
                outcome = event.get("outcome")
                if outcome:
                    self.results_panel.add_outcome(outcome)
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_metrics(metrics)
                if self.last_scan_started_at:
                    elapsed = (datetime.now() - self.last_scan_started_at).total_seconds()
                    self.elapsed_var.set(f"{elapsed:.2f}s")

            elif event_type == "scan_done":
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_metrics(metrics)
                duration = float(event.get("duration", 0.0) or 0.0)
                self.elapsed_var.set(f"{duration:.2f}s")
                self.last_report_path = event.get("report_path")
                cancelled = bool(event.get("cancelled"))
                self.progress_text_var.set("Scan cancelled" if cancelled else "Scan completed")
                self._set_state("completed")
                self._refresh_history()

            elif event_type == "scan_failed":
                self.log_panel.append(f"[ERROR] Scan failed: {event.get('message', 'unknown')}\n")
                self.progress_text_var.set("Scan failed")
                self._set_state("error")

            elif event_type == "boot_done":
                exit_code = int(event.get("exit_code", 1))
                if exit_code == 0:
                    self.log_panel.append(f"[SUCCESS] Sync data completed ({JSON_OUTPUT}).\n")
                    self.progress_text_var.set("Sync data completed")
                    self._set_state("completed")
                else:
                    self.log_panel.append(f"[ERROR] Sync data failed: {event.get('message', 'unknown')}\n")
                    self.progress_text_var.set("Sync data failed")
                    self._set_state("error")

            elif event_type == "history_rows":
                rows = event.get("rows") or []
                self.history_panel.set_rows(rows)

            elif event_type == "history_error":
                self.log_panel.append(f"[WARNING] Cannot load history: {event.get('message', '')}\n")

        self.after(100, self._drain_events)


def run() -> None:
    app = MainWindow()
    app.mainloop()
