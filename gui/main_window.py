import io
import os
import queue
import threading
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from app import JSON_OUTPUT, boot
from config import Config
from malware_scanner.reporting import write_report
from malware_scanner.scanner import ScanStore, ScannerEngine
from gui.components.history_panel import HistoryPanel
from gui.components.log_panel import LogPanel
from gui.components.results_panel import ResultsPanel


class QueueWriter(io.TextIOBase):
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue

    def write(self, text: str) -> int:
        cleaned = text.strip()
        if cleaned:
            self.event_queue.put({"type": "log", "message": cleaned + "\n"})
        return len(text)

    def flush(self) -> None:
        return


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Malware Scanner - CustomTkinter")
        self.geometry("1366x820")
        self.minsize(1120, 720)

        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self.event_queue: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()

        self.scan_thread: threading.Thread | None = None
        self.boot_thread: threading.Thread | None = None
        self.history_thread: threading.Thread | None = None

        self.current_scanner: ScannerEngine | None = None
        self.last_report_path: str | None = None
        self.last_scan_started_at: datetime | None = None
        self.current_state = "idle"

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
        self._set_state("idle")
        self.path_entry.configure(state="readonly")
        self._refresh_history()
        self.after(120, self._drain_events)

    def _build_layout(self) -> None:
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

        controls = ctk.CTkFrame(self)
        controls.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        controls.grid_columnconfigure(1, weight=1)

        self.file_btn = ctk.CTkButton(controls, text="File", width=70, command=self._pick_file)
        self.file_btn.grid(row=0, column=0, padx=(8, 6), pady=8)
        self.path_entry = ctk.CTkEntry(controls, textvariable=self.path_var)
        self.path_entry.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=8)
        self.folder_btn = ctk.CTkButton(controls, text="Folder", width=80, command=self._pick_folder)
        self.folder_btn.grid(row=0, column=2, padx=6, pady=8)

        self.start_btn = ctk.CTkButton(controls, text="Start", width=100, command=self._start_scan)
        self.start_btn.grid(row=0, column=3, padx=6, pady=8)

        self.cancel_btn = ctk.CTkButton(controls, text="Cancel", width=100, command=self._cancel_scan)
        self.cancel_btn.grid(row=0, column=4, padx=6, pady=8)

        self.boot_btn = ctk.CTkButton(controls, text="Boot Data", width=110, command=self._start_boot)
        self.boot_btn.grid(row=0, column=5, padx=6, pady=8)

        self.export_btn = ctk.CTkButton(controls, text="Open Report", width=120, command=self._open_report)
        self.export_btn.grid(row=0, column=6, padx=(6, 10), pady=8)

        status = ctk.CTkFrame(self)
        status.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        for col in range(8):
            status.grid_columnconfigure(col, weight=1)

        self.progress = ctk.CTkProgressBar(status)
        self.progress.grid(row=0, column=0, columnspan=8, sticky="ew", padx=10, pady=(10, 6))
        self.progress.set(0)

        ctk.CTkLabel(status, textvariable=self.progress_text_var).grid(row=1, column=0, columnspan=6, sticky="w", padx=10, pady=(0, 8))
        ctk.CTkLabel(status, text="State:").grid(row=1, column=6, sticky="e", padx=(0, 6), pady=(0, 8))
        ctk.CTkLabel(status, textvariable=self.state_var).grid(row=1, column=7, sticky="w", padx=(0, 10), pady=(0, 8))

        metrics = ctk.CTkFrame(self)
        metrics.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        for col in range(6):
            metrics.grid_columnconfigure(col, weight=1)

        self._metric_card(metrics, 0, "Total", self.total_var)
        self._metric_card(metrics, 1, "Hash", self.hash_var)
        self._metric_card(metrics, 2, "YARA", self.yara_var)
        self._metric_card(metrics, 3, "Clean", self.clean_var)
        self._metric_card(metrics, 4, "Error", self.err_var)
        self._metric_card(metrics, 5, "Elapsed", self.elapsed_var)

        workspace = ctk.CTkFrame(self)
        workspace.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 8))
        workspace.grid_rowconfigure(0, weight=1)
        workspace.grid_columnconfigure(0, weight=1)

        self.tabs = ctk.CTkTabview(workspace)
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.tabs.add("Results")
        self.tabs.add("History")

        self.results_panel = ResultsPanel(self.tabs.tab("Results"))
        self.results_panel.pack(fill="both", expand=True)

        self.history_panel = HistoryPanel(self.tabs.tab("History"))
        self.history_panel.pack(fill="both", expand=True)
        self.history_panel.set_refresh_handler(self._refresh_history)

        self.log_panel = LogPanel(self)
        self.log_panel.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.grid_rowconfigure(4, weight=1)

    def _metric_card(self, parent, col: int, label: str, value_var: ctk.StringVar) -> None:
        box = ctk.CTkFrame(parent)
        box.grid(row=0, column=col, sticky="ew", padx=6, pady=8)
        ctk.CTkLabel(box, text=label).pack(anchor="w", padx=10, pady=(8, 2))
        ctk.CTkLabel(box, textvariable=value_var, font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", padx=10, pady=(0, 10)
        )

    def _set_state(self, state: str) -> None:
        self.current_state = state
        self.state_var.set(state.upper())

        if state == "idle":
            self.file_btn.configure(state="normal")
            self.folder_btn.configure(state="normal")
            self.start_btn.configure(state="normal")
            self.boot_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.export_btn.configure(state="normal" if self.last_report_path else "disabled")
            return

        if state == "scanning":
            self.file_btn.configure(state="disabled")
            self.folder_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.boot_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
            self.export_btn.configure(state="disabled")
            return

        if state == "canceling":
            self.file_btn.configure(state="disabled")
            self.folder_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.boot_btn.configure(state="disabled")
            self.cancel_btn.configure(state="disabled")
            self.export_btn.configure(state="disabled")
            return

        if state == "booting":
            self.file_btn.configure(state="disabled")
            self.folder_btn.configure(state="disabled")
            self.start_btn.configure(state="disabled")
            self.boot_btn.configure(state="disabled")
            self.cancel_btn.configure(state="disabled")
            self.export_btn.configure(state="normal" if self.last_report_path else "disabled")
            return

        if state in {"completed", "error"}:
            self.file_btn.configure(state="normal")
            self.folder_btn.configure(state="normal")
            self.start_btn.configure(state="normal")
            self.boot_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.export_btn.configure(state="normal" if self.last_report_path else "disabled")
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
        self.progress_text_var.set("Running boot data process...")
        self.boot_thread = threading.Thread(target=self._run_boot_worker, daemon=True)
        self.boot_thread.start()

    def _run_boot_worker(self) -> None:
        writer = QueueWriter(self.event_queue)
        with redirect_stdout(writer), redirect_stderr(writer):
            exit_code = boot()
        self.event_queue.put({"type": "boot_done", "exit_code": exit_code})

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
        self.progress_text_var.set(f"Scanning: {target}")

        self.scan_thread = threading.Thread(target=self._run_scan_worker, args=(str(target),), daemon=True)
        self.scan_thread.start()

    def _run_scan_worker(self, target_path: str) -> None:
        writer = QueueWriter(self.event_queue)
        scanner = None
        start = datetime.now()

        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                scanner = ScannerEngine(
                    rules_path=Config.YARA_RULES_PATH,
                    event_callback=self._on_scanner_event,
                    cancel_event=self.cancel_event,
                )
                self.current_scanner = scanner

                target = Path(target_path)
                if target.is_file():
                    scanner.scan(target_path)
                    duration = (datetime.now() - start).total_seconds()
                    metrics = dict(scanner.metrics)
                else:
                    metrics, duration = scanner.scan_dir(target_path)

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

    def _on_scanner_event(self, event: dict) -> None:
        self.event_queue.put(event)

    def _cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self._set_state("canceling")
            self.progress_text_var.set("Cancel requested. Waiting workers to stop...")

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
                # Linux/macOS fallback
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
                self.log_panel.append(event.get("message", ""))
            elif event_type == "file_scanned":
                outcome = event.get("outcome")
                if outcome:
                    self.results_panel.add_outcome(outcome)
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_metrics(metrics)
                if self.last_scan_started_at:
                    elapsed = (datetime.now() - self.last_scan_started_at).total_seconds()
                    self.elapsed_var.set(f"{elapsed:.2f}s")
            elif event_type == "file_error":
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_metrics(metrics)
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
                self._set_state("error")
            elif event_type == "boot_done":
                exit_code = int(event.get("exit_code", 1))
                if exit_code == 0:
                    self.log_panel.append(f"[SUCCESS] Boot data completed ({JSON_OUTPUT}).\n")
                    self._set_state("completed")
                else:
                    self.log_panel.append("[ERROR] Boot data failed.\n")
                    self._set_state("error")
            elif event_type == "history_rows":
                rows = event.get("rows") or []
                self.history_panel.set_rows(rows)
            elif event_type == "history_error":
                self.log_panel.append(f"[WARNING] Cannot load history: {event.get('message', '')}\n")

        self.after(120, self._drain_events)


def run() -> None:
    app = MainWindow()
    app.mainloop()
