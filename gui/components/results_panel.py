from datetime import datetime
from tkinter import ttk

import customtkinter as ctk


class ResultsPanel(ctk.CTkFrame):
    COLUMNS = ("time", "file", "status", "method", "signature", "sha256")

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        filter_row = ctk.CTkFrame(self, fg_color="transparent")
        filter_row.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        filter_row.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar(value="")
        self.status_var = ctk.StringVar(value="ALL")
        self.method_var = ctk.StringVar(value="ALL")

        ctk.CTkEntry(filter_row, textvariable=self.search_var, placeholder_text="Search file/hash/signature").grid(
            row=0, column=0, sticky="ew", padx=(0, 8)
        )
        ctk.CTkOptionMenu(filter_row, variable=self.status_var, values=["ALL", "CLEAN", "DETECTED"]).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkOptionMenu(filter_row, variable=self.method_var, values=["ALL", "CLEAN", "HASH_MATCH", "YARA_MATCH"]).grid(row=0, column=2)

        tree_frame = ctk.CTkFrame(self)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, columns=self.COLUMNS, show="headings", height=12)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        headers = {
            "time": "Time",
            "file": "File",
            "status": "Status",
            "method": "Method",
            "signature": "Signature",
            "sha256": "SHA256",
        }
        widths = {"time": 140, "file": 180, "status": 90, "method": 120, "signature": 220, "sha256": 260}

        for col in self.COLUMNS:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=widths[col], anchor="w")

        self.detail = ctk.CTkTextbox(self, height=90)
        self.detail.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.detail.configure(state="disabled")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        self.status_var.trace_add("write", lambda *_: self._apply_filters())
        self.method_var.trace_add("write", lambda *_: self._apply_filters())

        self._rows: list[dict] = []
        self._item_to_row: dict[str, dict] = {}
        self._sort_column = "time"
        self._sort_desc = True

    def add_outcome(self, outcome: dict) -> None:
        detection = outcome.get("detection", {})
        method = str(detection.get("method", "CLEAN"))
        signature = str(detection.get("signature", "None"))
        status = "DETECTED" if method in ("HASH_MATCH", "YARA_MATCH") else "CLEAN"

        stage_timings = outcome.get("stage_timings", {}) or {}
        duration_ms = int((sum(stage_timings.values()) if isinstance(stage_timings, dict) else 0.0) * 1000)

        row = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "file": outcome.get("filename", ""),
            "status": status,
            "method": method,
            "signature": signature,
            "sha256": outcome.get("hash", {}).get("sha256", ""),
            "target_path": outcome.get("target_path", ""),
            "duration_ms": duration_ms,
            "raw": outcome,
        }
        self._rows.append(row)
        self._apply_filters()

    def clear(self) -> None:
        self._rows.clear()
        self._item_to_row.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.configure(state="disabled")

    def _apply_filters(self) -> None:
        search_text = self.search_var.get().strip().lower()
        status_filter = self.status_var.get()
        method_filter = self.method_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self._item_to_row.clear()

        rows = list(self._rows)
        rows.sort(key=lambda row: self._sort_key(row, self._sort_column), reverse=self._sort_desc)

        for row in rows:
            if status_filter != "ALL" and row["status"] != status_filter:
                continue
            if method_filter != "ALL" and row["method"] != method_filter:
                continue

            haystack = f"{row['file']} {row['sha256']} {row['signature']}".lower()
            if search_text and search_text not in haystack:
                continue
            values = (row["time"], row["file"], row["status"], row["method"], row["signature"], row["sha256"])
            item_id = self.tree.insert("", "end", values=values)
            self._item_to_row[item_id] = row

    def _sort_key(self, row: dict, column: str):
        if column == "time":
            return row.get("time", "")
        return str(row.get(column, "")).lower()

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_column = column
            self._sort_desc = False
        self._apply_filters()

    def _on_select(self, _event=None) -> None:
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
