"""
Main TUI application for YARA Malware Scanner.

Uses Textual framework for terminal-based user interface.
Provides file browser, scan progress, results table, and rule viewer.
"""

import os
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static
from textual.containers import Container, Horizontal

from .screens.main import MainScreen
from .screens.results import ResultsScreen
from .screens.rules import RulesScreen


class MalwareScannerApp(App):
    """
    YARA Malware Scanner Terminal UI.

    Provides interactive interface for:
    - File/directory selection
    - Scan progress monitoring
    - Results viewing and filtering
    - YARA rule browsing
    """

    CSS_PATH = "styles/main.tcss"

    TITLE = "YARA Malware Scanner"

    SCREENS = {
        "main": MainScreen,
        "results": ResultsScreen,
        "rules": RulesScreen,
    }

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("1", "show_main", "Scanner"),
        ("2", "show_results", "Results"),
        ("3", "show_rules", "Rules"),
        ("d", "toggle_dark", "Dark mode"),
    ]

    def on_mount(self) -> None:
        self.push_screen("main")

    def action_show_main(self) -> None:
        self.push_screen("main")

    def action_show_results(self) -> None:
        self.push_screen("results")

    def action_show_rules(self) -> None:
        self.push_screen("rules")

    def action_toggle_dark(self) -> None:
        self.dark = not self.dark


def run_tui():
    """Launch the TUI application."""
    app = MalwareScannerApp()
    app.run()


if __name__ == "__main__":
    run_tui()
