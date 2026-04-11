from datetime import datetime
from tkinter import ttk

import customtkinter as ctk


class ResultsPanel(ctk.CTkFrame):
    COLUMNS = ("time", "file", "status", "method", "signature", "sha256")

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self,
            text="Kết quả quét",
            text_color="#475569",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 2))

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 4))
        toolbar.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar(value="")
        self.status_var = ctk.StringVar(value="ALL")

        ctk.CTkEntry(
            toolbar,
            textvariable=self.search_var,
            placeholder_text="Tìm kiếm kết quả quét.",
        ).grid(
            row=0, column=0, sticky="ew", padx=(0, 8)
        )
        ctk.CTkOptionMenu(toolbar, variable=self.status_var, values=["ALL", "CLEAN", "DETECTED"]).grid(row=0, column=1, padx=(0, 8))
        self.report_btn = ctk.CTkButton(toolbar, text="Xuất báo cáo", width=120, state="disabled")
        self.report_btn.grid(row=0, column=2)

        split_view = ttk.Panedwindow(self, orient="vertical")
        split_view.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))

        tree_frame = ctk.CTkFrame(split_view)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, columns=self.COLUMNS, show="headings", height=12)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        x_scrollbar.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=scrollbar.set, xscrollcommand=x_scrollbar.set)

        headers = {
            "time": "Time",
            "file": "File",
            "status": "Status",
            "method": "Method",
            "signature": "Signature",
            "sha256": "SHA256",
        }
        widths = {"time": 120, "file": 220, "status": 100, "method": 130, "signature": 300, "sha256": 360}

        for col in self.COLUMNS:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self._toggle_sort(c))
            stretch = col in {"file", "signature", "sha256"}
            self.tree.column(col, width=widths[col], minwidth=90, anchor="w", stretch=stretch)

        detail_frame = ctk.CTkFrame(split_view)
        detail_frame.grid_rowconfigure(0, weight=1)
        detail_frame.grid_columnconfigure(0, weight=1)

        self.detail = ctk.CTkTextbox(detail_frame)
        self.detail.grid(row=0, column=0, sticky="nsew")
        self.detail.configure(state="disabled")

        split_view.add(tree_frame, weight=4)
        split_view.add(detail_frame, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._show_selected)
        self.search_var.trace_add("write", lambda *_: self._refresh_rows())
        self.status_var.trace_add("write", lambda *_: self._refresh_rows())

        self._rows: list[dict] = []
        self._item_to_row: dict[str, dict] = {}
        self._sort_column = "time"
        self._sort_desc = True

    def on_export(self, handler) -> None:
        self.report_btn.configure(command=handler)

    def set_export_enabled(self, enabled: bool) -> None:
        self.report_btn.configure(state="normal" if enabled else "disabled")

    def add_result(self, scan_result: dict) -> None:
        hit = scan_result.get("detection", {})
        method = str(hit.get("method", "CLEAN"))
        signature = str(hit.get("signature", "None"))
        status = "DETECTED" if method in ("HASH_MATCH", "YARA_MATCH") else "CLEAN"

        timings = scan_result.get("stage_timings", {}) or {}
        duration_ms = int((sum(timings.values()) if isinstance(timings, dict) else 0.0) * 1000)

        row = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "file": scan_result.get("filename", ""),
            "status": status,
            "method": method,
            "signature": signature,
            "sha256": scan_result.get("hash", {}).get("sha256", ""),
            "target_path": scan_result.get("target_path", ""),
            "duration_ms": duration_ms,
            "raw": scan_result,
        }
        self._rows.append(row)
        self._refresh_rows()

    def clear(self) -> None:
        self._rows.clear()
        self._item_to_row.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.configure(state="disabled")

    def _refresh_rows(self) -> None:
        tokens = [token for token in self.search_var.get().strip().lower().split() if token]
        status = self.status_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self._item_to_row.clear()

        rows = list(self._rows)
        rows.sort(key=lambda row: self._row_key(row, self._sort_column), reverse=self._sort_desc)

        for row in rows:
            if status != "ALL" and row["status"] != status:
                continue

            text_blob = " ".join(str(row.get(col, "")) for col in self.COLUMNS).lower()
            if tokens and not all(token in text_blob for token in tokens):
                continue
            values = (row["time"], row["file"], row["status"], row["method"], row["signature"], row["sha256"])
            item_id = self.tree.insert("", "end", values=values)
            self._item_to_row[item_id] = row

    def _row_key(self, row: dict, column: str):
        if column == "time":
            return row.get("time", "")
        return str(row.get(column, "")).lower()

    def _toggle_sort(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_column = column
            self._sort_desc = False
        self._refresh_rows()

    def _show_selected(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        row = self._item_to_row.get(item_id)
        if not row:
            values = self.tree.item(item_id, "values")
            detail = (
                f"Time: {values[0]}\n"
                f"File: {values[1]}\n"
                f"Status: {values[2]}\n"
                f"Method: {values[3]}\n"
                f"Signature: {values[4]}\n"
                f"SHA256: {values[5]}\n"
            )
            self.detail.configure(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", detail)
            self.detail.configure(state="disabled")
            return

        raw = row.get("raw", {})
        hashes = raw.get("hash", {})
        stage_timings = raw.get("stage_timings", {}) or {}
        detail = (
            f"Time: {row['time']}\n"
            f"File: {row['file']}\n"
            f"Path: {row.get('target_path', '')}\n"
            f"Status: {row['status']}\n"
            f"Method: {row['method']}\n"
            f"Signature: {row['signature']}\n"
            f"SHA256: {row['sha256']}\n"
            f"MD5: {hashes.get('md5', '')}\n"
            f"SHA1: {hashes.get('sha1', '')}\n"
            f"SHA3_384: {hashes.get('sha3_384', '')}\n"
            f"MIME: {raw.get('file_mime_type', '')}\n"
            f"Extension: {raw.get('file_extension', '')}\n"
            f"Duration: {row.get('duration_ms', 0)} ms\n"
            f"Stage timings: {stage_timings}\n"
        )
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", detail)
        self.detail.configure(state="disabled")
