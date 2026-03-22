"""
Results screen for viewing detailed scan results.

Displays all scan results in a sortable table with
filtering and export capabilities.
"""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Static, Button
from textual.containers import Container


class ResultsScreen(Screen):
    """
    Detailed scan results view.

    Shows all scan results with sorting and filtering.
    """

    BINDINGS = [
        ("escape", "pop_screen", "Back"),
        ("e", "export", "Export"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("[bold]SCAN RESULTS[/bold]", classes="screen-title")

        with Container(id="results-container"):
            yield DataTable(id="full-results")

        with Container(id="actions"):
            yield Button("Export CSV", id="export-btn")
            yield Button("Back", id="back-btn")

    def on_mount(self) -> None:
        table = self.query_one("#full-results", DataTable)
        table.add_columns("File", "Path", "Rule", "Method", "SHA256", "Time")
        table.cursor_type = "row"
        table.zebra_stripes = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back-btn":
            self.app.pop_screen()
        elif event.button.id == "export-btn":
            self.action_export()

    def action_export(self) -> None:
        self.notify("Export not implemented yet")
