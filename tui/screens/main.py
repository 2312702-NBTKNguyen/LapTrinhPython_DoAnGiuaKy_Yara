"""
Main screen for YARA Malware Scanner TUI.

Provides file browser on the left, scan results on the right,
and progress bar at the bottom.
"""

import os
import asyncio
from pathlib import Path

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    DirectoryTree,
    DataTable,
    ProgressBar,
    Button,
    Static,
    Header,
    Footer,
)
from textual.containers import Container, Horizontal, Vertical
from textual import work


class MalwareFileTree(DirectoryTree):
    """File tree with filtering for scan targets."""

    EXCLUDE_PATTERNS = {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "/proc",
        "/sys",
        "/dev",
    }

    def filter_paths(self, paths):
        """Filter out system directories and hidden files."""
        return [
            path
            for path in paths
            if not any(excl in str(path) for excl in self.EXCLUDE_PATTERNS)
            and not path.name.startswith(".")
        ]


class ScanResultsTable(DataTable):
    """Table displaying scan results with severity coloring."""

    COLUMNS = [
        ("file", "File Path", 40),
        ("rule", "YARA Match", 25),
        ("severity", "Severity", 12),
        ("size", "Size", 10),
    ]

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        for col_id, label, width in self.COLUMNS:
            self.add_column(label, key=col_id, width=width)


class MainScreen(Screen):
    """
    Main scanner interface.

    Layout:
    - Left: File/directory browser
    - Right: Scan results table
    - Bottom: Progress bar and status
    """

    BINDINGS = [
        ("s", "start_scan", "Start Scan"),
        ("enter", "select_target", "Select"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal():
            # Left panel: File browser
            with Vertical(id="browser-panel"):
                yield Static("[bold]SCAN TARGETS[/bold]", classes="panel-title")
                yield MalwareFileTree(Path.home(), id="file-tree")
                yield Button("Scan Selected", id="scan-btn", variant="primary")

            # Right panel: Results
            with Vertical(id="results-panel"):
                yield Static("[bold]SCAN RESULTS[/bold]", classes="panel-title")
                yield ScanResultsTable(id="results-table")

        # Bottom: Progress
        with Container(id="progress-container"):
            yield ProgressBar(id="scan-progress", show_eta=False)
            yield Static("Ready.", id="status-text")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-btn":
            self.action_start_scan()

    def action_start_scan(self) -> None:
        tree = self.query_one("#file-tree", MalwareFileTree)
        if hasattr(tree, "path"):
            self.start_scan(str(tree.path))

    @work(exclusive=True)
    async def start_scan(self, target_path: str) -> None:
        """Run scan in background worker."""
        progress = self.query_one("#scan-progress", ProgressBar)
        status = self.query_one("#status-text", Static)
        table = self.query_one("#results-table", ScanResultsTable)

        status.update(f"[bold green]Scanning: {target_path}[/bold green]")
        progress.update(total=None)

        from malware_scanner.service import MalwareScanner
        from malware_scanner.engine import load_yara_rules

        try:
            rules = await asyncio.to_thread(load_yara_rules, "rules/index.yar")
            scanner = await asyncio.to_thread(
                lambda: MalwareScanner(rules_path="rules/index.yar")
            )

            if os.path.isfile(target_path):
                result = await asyncio.to_thread(scanner.scan_target, target_path)
                if result:
                    self._add_result(table, target_path, result)
            elif os.path.isdir(target_path):
                for root, dirs, files in os.walk(target_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        result = await asyncio.to_thread(scanner.scan_target, filepath)
                        if result:
                            self._add_result(table, filepath, result)
                        await asyncio.sleep(0)

            scanner.close()
            status.update("[bold]Scan complete.[/bold]")

        except Exception as e:
            status.update(f"[bold red]Error: {e}[/bold red]")

    def _add_result(self, table: DataTable, filepath: str, result) -> None:
        """Add scan result to table."""
        severity = "HIGH" if result.get("yara_match") else "CLEAN"
        table.add_row(
            Path(filepath).name,
            result.get("match", "-"),
            severity,
            str(result.get("size", 0)),
        )
