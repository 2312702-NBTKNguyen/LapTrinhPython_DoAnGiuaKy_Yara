from datetime import datetime
from tkinter import ttk

import customtkinter as ctk


class HistoryPanel(ctk.CTkFrame):
    COLUMNS = ("id", "time", "file", "path", "method")

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        controls.grid_columnconfigure(0, weight=1)

        self.search_var = ctk.StringVar(value="")
        self.method_var = ctk.StringVar(value="ALL")
        ctk.CTkEntry(controls, textvariable=self.search_var, placeholder_text="Search by file/path").grid(
            row=0, column=0, sticky="ew", padx=(0, 8)
        )
        ctk.CTkOptionMenu(controls, variable=self.method_var, values=["ALL", "CLEAN", "HASH_MATCH", "YARA_MATCH"]).grid(
            row=0, column=1, padx=(0, 8)
        )
        self.refresh_btn = ctk.CTkButton(controls, text="Refresh", width=90, command=lambda: None)
        self.refresh_btn.grid(row=0, column=2)

        table = ctk.CTkFrame(self)
        table.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(table, columns=self.COLUMNS, show="headings", height=10)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        x_scrollbar.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=scrollbar.set, xscrollcommand=x_scrollbar.set)

        headers = {
            "id": "ID",
            "time": "ScanTime",
            "file": "File",
            "path": "Path",
            "method": "Method",
        }
        widths = {"id": 70, "time": 170, "file": 220, "path": 440, "method": 130}
        for col in self.COLUMNS:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self._sort_by(c))
            stretch = col in {"file", "path"}
            self.tree.column(col, width=widths[col], minwidth=90, anchor="w", stretch=stretch)

        self.detail = ctk.CTkTextbox(self, height=90)
        self.detail.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.detail.configure(state="disabled")

        self._rows: list[tuple] = []
        self._item_to_row: dict[str, tuple] = {}
        self._sort_column = "time"
        self._sort_desc = True
        self.search_var.trace_add("write", lambda *_: self._apply_filters())
        self.method_var.trace_add("write", lambda *_: self._apply_filters())
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

    def set_refresh_handler(self, handler):
        self.refresh_btn.configure(command=handler)

    def set_rows(self, rows: list[tuple]) -> None:
        self._rows = rows
        self._apply_filters()

    def _apply_filters(self) -> None:
        term = self.search_var.get().strip().lower()
        method_filter = self.method_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self._item_to_row.clear()

        rows = list(self._rows)
        rows.sort(key=lambda row: self._sort_key(row, self._sort_column), reverse=self._sort_desc)

        for rec_id, file_name, file_path, method, scan_time in rows:
            if isinstance(scan_time, datetime):
                scan_text = scan_time.strftime("%Y-%m-%d %H:%M:%S")
            else:
                scan_text = str(scan_time)

            if method_filter != "ALL" and method != method_filter:
                continue

            haystack = f"{file_name} {file_path}".lower()
            if term and term not in haystack:
                continue

            item_id = self.tree.insert("", "end", values=(rec_id, scan_text, file_name, file_path, method))
            self._item_to_row[item_id] = (rec_id, file_name, file_path, method, scan_time)

    def _sort_key(self, row: tuple, column: str):
        rec_id, file_name, file_path, method, scan_time = row
        if column == "id":
            return int(rec_id)
        if column == "time":
            return scan_time if isinstance(scan_time, datetime) else str(scan_time)
        if column == "file":
            return str(file_name).lower()
        if column == "path":
            return str(file_path).lower()
        if column == "method":
            return str(method).lower()
        return str(row)

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
            return

        rec_id, file_name, file_path, method, scan_time = row
        if isinstance(scan_time, datetime):
            scan_text = scan_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            scan_text = str(scan_time)

        detail = (
            f"Scan Result ID: {rec_id}\n"
            f"Scan Time: {scan_text}\n"
            f"File: {file_name}\n"
            f"Path: {file_path}\n"
            f"Method: {method}\n"
        )
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", detail)
        self.detail.configure(state="disabled")
