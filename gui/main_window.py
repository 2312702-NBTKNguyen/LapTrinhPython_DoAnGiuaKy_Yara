import io
import os
import queue
import re
import threading

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from config import Config
from data_tools.data_loader import sync_sigs
from data_tools.db_setup import init_db
from gui.components.history_panel import HistoryPanel
from gui.components.log_panel import LogPanel
from gui.components.results_panel import ResultsPanel
from malware_scanner.reporting import save_report
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


LOG_PREFIX_PATTERN = re.compile(r"^\[(INFO|SUCCESS|WARNING|ERROR)\]\s*", re.IGNORECASE)


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Hybrid Malware Scanner")
        self._window_size = (1440, 860)
        self._last_window_state = "normal"
        self.geometry(f"{self._window_size[0]}x{self._window_size[1]}")
        self.minsize(1180, 760)

        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        self._style_tree()

        self.event_queue: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.scan_thread: threading.Thread | None = None
        self.boot_thread: threading.Thread | None = None
        self.history_thread: threading.Thread | None = None

        self.current_state = "idle"
        self.last_scan_started_at: datetime | None = None
        self.last_report_path: str | None = None

        self.path_var = ctk.StringVar(value="")
        self.state_var = ctk.StringVar(value="IDLE")
        self.progress_text_var = ctk.StringVar(value="Ready")

        self.total_var = ctk.StringVar(value="0")
        self.hash_var = ctk.StringVar(value="0")
        self.yara_var = ctk.StringVar(value="0")
        self.clean_var = ctk.StringVar(value="0")
        self.err_var = ctk.StringVar(value="0")
        self.elapsed_var = ctk.StringVar(value="0.00s")

        self._build_ui()
        self._center_window(*self._window_size)
        self.bind("<Configure>", self._on_window_state_change)
        self._set_mode("idle")
        self._load_history()
        self.after(100, self._pump_events)

    def _center_window(self, width: int | None = None, height: int | None = None) -> None:
        self.update_idletasks()
        win_w = width if width is not None else self.winfo_width()
        win_h = height if height is not None else self.winfo_height()

        if win_w <= 1 or win_h <= 1:
            return

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        pos_x = max(0, (screen_w - win_w) // 2)
        pos_y = max(0, (screen_h - win_h) // 2)
        self.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

    def _on_window_state_change(self, _event=None) -> None:
        current_state = self.state()
        if current_state == "normal" and self._last_window_state == "zoomed":
            self.after_idle(self._center_window)
        self._last_window_state = current_state

    def _style_tree(self) -> None:
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

    def _build_ui(self) -> None:
        self.configure(fg_color="#f3f6fb")

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_top()
        self._build_stats()
        self._build_body()
        self._build_bottom()

    def _build_top(self) -> None:
        header = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=16)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        header.grid_columnconfigure(1, weight=1)

        identity = ctk.CTkFrame(header, fg_color="transparent")
        identity.grid(row=0, column=0, sticky="w", padx=(14, 8), pady=12)
        ctk.CTkLabel(
            identity,
            text="Lập trình Python",
            font=ctk.CTkFont(family="Segoe UI Semibold", size=24, weight="bold"),
            text_color="#0f172a",
        ).pack(anchor="w")
        ctk.CTkLabel(
            identity,
            text="Ứng dụng thư viện YARA trong phát hiện Malware",
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
            placeholder_text="Nhập hoặc chọn đường dẫn file/thư mục cần quét...",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        )
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.file_btn = ctk.CTkButton(
            controls,
            text="Chọn File",
            width=74,
            height=38,
            corner_radius=12,
            command=self._choose_file,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.file_btn.grid(row=0, column=1, padx=4)

        self.folder_btn = ctk.CTkButton(
            controls,
            text="Chọn Thư mục",
            width=84,
            height=38,
            corner_radius=12,
            command=self._choose_folder,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.folder_btn.grid(row=0, column=2, padx=4)

        self.start_btn = ctk.CTkButton(
            controls,
            text="Quét",
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
            text="Dừng",
            width=86,
            height=38,
            corner_radius=12,
            fg_color="#b91c1c",
            hover_color="#991b1b",
            command=self._cancel_job,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.cancel_btn.grid(row=0, column=4, padx=4)

        self.boot_btn = ctk.CTkButton(
            controls,
            text="Khởi tạo dữ liệu",
            width=98,
            height=38,
            corner_radius=12,
            command=self._start_sync,
            font=ctk.CTkFont(family="Segoe UI Semibold", size=12),
        )
        self.boot_btn.grid(row=0, column=5, padx=4)


    def _build_stats(self) -> None:
        metrics = ctk.CTkFrame(self, fg_color="#ffffff", corner_radius=16)
        metrics.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))

        for col in range(6):
            metrics.grid_columnconfigure(col, weight=1)

        self._add_stat_card(metrics, 0, "Tổng số file đã quét", self.total_var, "#2563eb")
        self._add_stat_card(metrics, 1, "Hash Match", self.hash_var, "#dc2626")
        self._add_stat_card(metrics, 2, "YARA Match", self.yara_var, "#ea580c")
        self._add_stat_card(metrics, 3, "Clean", self.clean_var, "#0f766e")
        self._add_stat_card(metrics, 4, "Lỗi", self.err_var, "#b91c1c")
        self._add_stat_card(metrics, 5, "Thời gian quét", self.elapsed_var, "#4f46e5")

    def _add_stat_card(self, parent, col: int, title: str, value_var: ctk.StringVar, accent: str) -> None:
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

    def _build_body(self) -> None:
        workspace = ctk.CTkFrame(self, fg_color="transparent")
        workspace.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 8))
        workspace.grid_rowconfigure(0, weight=1)
        workspace.grid_columnconfigure(0, weight=1)

        horizontal_pane = ttk.Panedwindow(workspace, orient="horizontal")
        horizontal_pane.grid(row=0, column=0, sticky="nsew")

        self.results_panel = ResultsPanel(horizontal_pane, fg_color="#ffffff", corner_radius=16)
        self.results_panel.on_export(self._open_last_report)
        self.results_panel.set_export_enabled(False)

        vertical_pane = ttk.Panedwindow(horizontal_pane, orient="vertical")

        self.history_panel = HistoryPanel(vertical_pane, fg_color="#ffffff", corner_radius=16)
        self.history_panel.on_refresh(self._load_history)

        self.log_panel = LogPanel(vertical_pane, fg_color="#ffffff", corner_radius=16)

        horizontal_pane.add(self.results_panel, weight=3)
        horizontal_pane.add(vertical_pane, weight=2)
        vertical_pane.add(self.history_panel, weight=1)
        vertical_pane.add(self.log_panel, weight=1)

    def _build_bottom(self) -> None:
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

    def _set_mode(self, state: str) -> None:
        mode_map: dict[str, tuple[str, str, str, str, str, bool]] = {
            "idle": ("normal", "normal", "normal", "normal", "disabled", bool(self.last_report_path)),
            "scanning": ("disabled", "disabled", "disabled", "disabled", "normal", False),
            "canceling": ("disabled", "disabled", "disabled", "disabled", "disabled", False),
            "booting": ("disabled", "disabled", "disabled", "disabled", "disabled", bool(self.last_report_path)),
            "completed": ("normal", "normal", "normal", "normal", "disabled", bool(self.last_report_path)),
            "error": ("normal", "normal", "normal", "normal", "disabled", bool(self.last_report_path)),
        }

        if state not in mode_map:
            state = "idle"

        self.current_state = state
        self.state_var.set(state.upper())
        file_state, folder_state, start_state, boot_state, cancel_state, can_export = mode_map[state]
        self.file_btn.configure(state=file_state)
        self.folder_btn.configure(state=folder_state)
        self.start_btn.configure(state=start_state)
        self.boot_btn.configure(state=boot_state)
        self.cancel_btn.configure(state=cancel_state)
        self.results_panel.set_export_enabled(can_export)

    def _choose_file(self) -> None:
        file_path = filedialog.askopenfilename(title="Chọn tệp để quét")
        if file_path:
            self.path_var.set(file_path)

    def _choose_folder(self) -> None:
        folder_path = filedialog.askdirectory(title="Chọn thư mục để quét")
        if folder_path:
            self.path_var.set(folder_path)

    def _start_sync(self) -> None:
        if self.boot_thread and self.boot_thread.is_alive():
            return

        self._set_mode("booting")
        self.progress_text_var.set("Đang đồng bộ dữ liệu signatures...")
        self.boot_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self.boot_thread.start()

    def _sync_worker(self) -> None:
        writer = QueueWriter(self.event_queue)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                JSON_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
                init_db()
                sync_sigs(JSON_OUTPUT)
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
            messagebox.showerror("Thiếu đường dẫn", "Vui lòng chọn tệp hoặc thư mục để quét.")
            return

        target = Path(raw_path).expanduser().resolve()
        if not target.exists():
            messagebox.showerror("Đường dẫn không hợp lệ", f"Đường dẫn không tồn tại:\n{target}")
            return

        self._reset_stats()
        self.results_panel.clear()
        self.cancel_event.clear()
        self.last_scan_started_at = datetime.now()
        self.last_report_path = None
        self._set_mode("scanning")
        self.progress_text_var.set(f"Đang quét: {target}")

        self.scan_thread = threading.Thread(target=self._scan_worker, args=(str(target),), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, target_path: str) -> None:
        scanner: ScannerEngine | None = None
        start = datetime.now()

        try:
            scanner = ScannerEngine(
                rules_path=Config.YARA_RULES_PATH,
                log_callback=self._push_log,
                result_callback=self._push_result,
                cancel_event=self.cancel_event,
            )

            target = Path(target_path)
            if target.is_file():
                scanner.scan(target_path)
                duration = (datetime.now() - start).total_seconds()
                metrics = dict(scanner.metrics)
            else:
                metrics, duration = scanner.scan_folder(target_path)

            report_path = save_report(scanner.store, start)
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

    def _push_log(self, payload: dict) -> None:
        self.event_queue.put(payload)

    def _push_result(self, payload: dict) -> None:
        self.event_queue.put(payload)

    def _cancel_job(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self._set_mode("canceling")
            self.progress_text_var.set("Đã yêu cầu dừng quét. Đang đợi phiên làm việc kết thúc...")

    def _open_last_report(self) -> None:
        if not self.last_report_path:
            return

        report_path = Path(self.last_report_path)
        if not report_path.exists():
            messagebox.showerror("Lỗi mở báo cáo", f"File báo cáo không tồn tại:\n{report_path}")
            return

        try:
            if os.name == "nt":
                os.startfile(report_path)  # type: ignore[attr-defined]
            else:
                os.system(f'xdg-open "{report_path}"')
        except Exception as exc:
            messagebox.showerror("Lỗi mở báo cáo", str(exc))

    def _load_history(self) -> None:
        if self.history_thread and self.history_thread.is_alive():
            return

        self.history_thread = threading.Thread(target=self._history_worker, daemon=True)
        self.history_thread.start()

    def _history_worker(self) -> None:
        store = ScanStore()
        try:
            rows = store.list_history(limit=300)
            self.event_queue.put({"type": "history_rows", "rows": rows})
        except Exception as exc:
            self.event_queue.put({"type": "history_error", "message": str(exc)})
        finally:
            store.close()

    def _reset_stats(self) -> None:
        self.total_var.set("0")
        self.hash_var.set("0")
        self.yara_var.set("0")
        self.clean_var.set("0")
        self.err_var.set("0")
        self.elapsed_var.set("0.00s")
        self.progress.set(0)

    def _update_stats(self, metrics: dict[str, int]) -> None:
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

    def _pump_events(self) -> None:
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
                    if LOG_PREFIX_PATTERN.match(message):
                        self.log_panel.append(f"{message}\n")
                    else:
                        self.log_panel.append(f"[{level}] {message}\n")
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_stats(metrics)

            elif event_type == "result":
                outcome = event.get("outcome")
                if outcome:
                    self.results_panel.add_result(outcome)
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_stats(metrics)
                if self.last_scan_started_at:
                    elapsed = (datetime.now() - self.last_scan_started_at).total_seconds()
                    self.elapsed_var.set(f"{elapsed:.2f}s")

            elif event_type == "scan_done":
                metrics = event.get("metrics")
                if isinstance(metrics, dict):
                    self._update_stats(metrics)
                duration = float(event.get("duration", 0.0) or 0.0)
                self.elapsed_var.set(f"{duration:.2f}s")
                self.last_report_path = event.get("report_path")
                cancelled = bool(event.get("cancelled"))
                self.progress_text_var.set("Hủy bỏ quét" if cancelled else "Quét hoàn tất")
                self._set_mode("completed")
                self._load_history()

            elif event_type == "scan_failed":
                self.log_panel.append(f"[ERROR] Quét thất bại: {event.get('message', 'unknown')}\n")
                self.progress_text_var.set("Quét thất bại")
                self._set_mode("error")

            elif event_type == "boot_done":
                exit_code = int(event.get("exit_code", 1))
                if exit_code == 0:
                    self.log_panel.append(f"[SUCCESS] Đồng bộ dữ liệu hoàn tất ({JSON_OUTPUT}).\n")
                    self.progress_text_var.set("Đồng bộ dữ liệu hoàn tất")
                    self._set_mode("completed")
                else:
                    self.log_panel.append(f"[ERROR] Đồng bộ dữ liệu thất bại: {event.get('message', 'unknown')}\n")
                    self.progress_text_var.set("Đồng bộ dữ liệu thất bại")
                    self._set_mode("error")

            elif event_type == "history_rows":
                rows = event.get("rows") or []
                self.history_panel.load_rows(rows)

            elif event_type == "history_error":
                self.log_panel.append(f"[WARNING] Không thể tải lịch sử: {event.get('message', '')}\n")

        self.after(100, self._pump_events)


def run() -> None:
    app = MainWindow()
    app.mainloop()
