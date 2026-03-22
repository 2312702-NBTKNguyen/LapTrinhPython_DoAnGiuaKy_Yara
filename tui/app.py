"""
YARA Malware Scanner TUI - Command-based Interface.

Provides a chat-like interface with /commands for:
- /scan <path> - Scan file or directory
- /file-system - Browse files
- /results - View scan results
- /rules - View YARA rules
- /help - Show available commands
- /quit - Exit application
"""

import asyncio
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Input, RichLog
from textual.containers import Container, Vertical
from textual import work

from .screens.commands import CommandHandler


class Dashboard(Static):
    """Main dashboard showing scan status and recent activity."""

    def compose(self) -> ComposeResult:
        yield Static("[bold green]YARA Malware Scanner[/bold green]", id="title")
        yield Static("", id="status")
        yield Static("", id="stats")
        yield RichLog(id="activity-log", highlight=True, wrap=True)

    def update_status(self, status: str) -> None:
        self.query_one("#status", Static).update(status)

    def update_stats(self, scanned: int, threats: int, clean: int) -> None:
        stats = (
            f"[bold]Scanned:[/bold] {scanned} | "
            f"[bold red]Threats:[/bold red] {threats} | "
            f"[bold green]Clean:[/bold green] {clean}"
        )
        self.query_one("#stats", Static).update(stats)

    def log_activity(self, message: str) -> None:
        log = self.query_one("#activity-log", RichLog)
        log.write(message)


class CommandInput(Input):
    """Command input with / prefix support."""

    def on_mount(self) -> None:
        self.placeholder = "Type / for commands..."
        self.focus()


class MalwareScannerApp(App):
    """
    YARA Malware Scanner TUI with command-based interface.
    """

    CSS = """
    Screen {
        background: $background;
    }

    #dashboard {
        height: 1fr;
        padding: 1;
    }

    #title {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }

    #status {
        margin-bottom: 1;
    }

    #stats {
        margin-bottom: 1;
        color: $text;
    }

    #activity-log {
        height: 1fr;
        border: solid $primary;
        margin-top: 1;
    }

    #command-container {
        dock: bottom;
        height: 5;
        background: $surface;
        border-top: solid $primary;
        padding: 1;
    }

    #command-input {
        width: 1fr;
    }

    CommandInput {
        background: $background;
        color: $text;
    }

    CommandInput:focus {
        border: tall $primary;
    }
    """

    TITLE = "YARA Malware Scanner"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.command_handler = CommandHandler(self)
        self.scan_count = 0
        self.threat_count = 0
        self.clean_count = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield Dashboard(id="dashboard")
        with Container(id="command-container"):
            yield CommandInput(id="command-input")
        yield Footer()

    def on_mount(self) -> None:
        dashboard = self.query_one("#dashboard", Dashboard)
        dashboard.update_status(
            "[bold yellow]Ready. Type /help for commands.[/bold yellow]"
        )
        dashboard.update_stats(0, 0, 0)
        dashboard.log_activity("[dim]Application started[/dim]")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command input."""
        command = event.value.strip()
        if command:
            self.process_command(command)
        event.input.clear()

    def process_command(self, command: str) -> None:
        """Process user command."""
        dashboard = self.query_one("#dashboard", Dashboard)
        dashboard.log_activity(f"[cyan]> {command}[/cyan]")

        if command.startswith("/"):
            self.command_handler.handle(command)
        else:
            dashboard.log_activity(
                "[red]Unknown command. Type /help for available commands.[/red]"
            )

    def update_stats(self) -> None:
        """Update dashboard statistics."""
        dashboard = self.query_one("#dashboard", Dashboard)
        dashboard.update_stats(self.scan_count, self.threat_count, self.clean_count)

    def log_activity(self, message: str) -> None:
        """Log activity to dashboard."""
        dashboard = self.query_one("#dashboard", Dashboard)
        dashboard.log_activity(message)


def run_tui():
    """Launch the TUI application."""
    app = MalwareScannerApp()
    app.run()


if __name__ == "__main__":
    run_tui()
