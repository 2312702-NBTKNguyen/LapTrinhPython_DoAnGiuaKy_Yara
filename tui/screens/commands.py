"""
Command handler for YARA Malware Scanner TUI.

Processes /commands and routes to appropriate handlers.
"""

import asyncio
from pathlib import Path

from textual.screen import ModalScreen
from textual.widgets import DirectoryTree, Static, Button
from textual.containers import Container, Horizontal
from textual.app import ComposeResult


class FileSystemBrowser(ModalScreen):
    """Modal file system browser."""

    def __init__(self, start_path: str = str(Path.home())):
        super().__init__()
        self.start_path = start_path
        self.selected_path = None

    def compose(self) -> ComposeResult:
        yield Container(
            Static("[bold]File System Browser[/bold]", classes="modal-title"),
            DirectoryTree(self.start_path, id="file-tree-modal"),
            Horizontal(
                Button("Select", id="select-btn", variant="primary"),
                Button("Cancel", id="cancel-btn"),
                classes="modal-buttons",
            ),
            id="file-browser-modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "select-btn":
            tree = self.query_one("#file-tree-modal", DirectoryTree)
            if hasattr(tree, "path"):
                self.selected_path = str(tree.path)
                self.dismiss(self.selected_path)
            else:
                self.dismiss(None)
        else:
            self.dismiss(None)

    def on_directory_tree_file_selected(self, event) -> None:
        self.selected_path = str(event.path)
        self.dismiss(self.selected_path)


class CommandHandler:
    """Handle /commands from the TUI."""

    COMMANDS = {
        "/help": "Show available commands",
        "/scan": "Scan file or directory (usage: /scan <path>)",
        "/file-system": "Browse file system",
        "/results": "View scan results",
        "/rules": "View YARA rules",
        "/clear": "Clear activity log",
        "/quit": "Exit application",
    }

    def __init__(self, app):
        self.app = app

    def handle(self, command: str) -> None:
        """Route command to appropriate handler."""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        handlers = {
            "/help": self.handle_help,
            "/scan": self.handle_scan,
            "/file-system": self.handle_file_system,
            "/results": self.handle_results,
            "/rules": self.handle_rules,
            "/clear": self.handle_clear,
            "/quit": self.handle_quit,
        }

        handler = handlers.get(cmd)
        if handler:
            handler(args)
        else:
            self.app.log_activity(
                f"[red]Unknown command: {cmd}. Type /help for available commands.[/red]"
            )

    def handle_help(self, args: str) -> None:
        """Show help message."""
        self.app.log_activity("[bold]Available commands:[/bold]")
        for cmd, desc in self.COMMANDS.items():
            self.app.log_activity(f"  [cyan]{cmd}[/cyan] - {desc}")

    def handle_scan(self, path: str) -> None:
        """Scan file or directory."""
        if not path:
            self.app.log_activity("[yellow]Usage: /scan <path>[/yellow]")
            self.app.log_activity(
                "[yellow]Or use /file-system to browse and select files.[/yellow]"
            )
            return

        if not Path(path).exists():
            self.app.log_activity(f"[red]Path not found: {path}[/red]")
            return

        self.app.log_activity(f"[green]Starting scan: {path}[/green]")
        self.start_scan(path)

    def handle_file_system(self, args: str) -> None:
        """Show file system browser."""
        self.app.log_activity("[yellow]Opening file system browser...[/yellow]")

        def on_file_selected(path):
            if path:
                self.app.log_activity(f"[green]Selected: {path}[/green]")
                self.app.log_activity(
                    "[yellow]Type /scan to scan the selected file.[/yellow]"
                )
            else:
                self.app.log_activity("[dim]File selection cancelled.[/dim]")

        browser = FileSystemBrowser()
        self.app.push_screen(browser, on_file_selected)

    def handle_results(self, args: str) -> None:
        """Show scan results."""
        self.app.log_activity("[bold]Recent scan results:[/bold]")
        self.app.log_activity("[dim]No results yet. Run /scan first.[/dim]")

    def handle_rules(self, args: str) -> None:
        """Show YARA rules."""
        self.app.log_activity("[bold]YARA Rules:[/bold]")
        rules_path = Path("rules")
        if rules_path.exists():
            for rule_file in rules_path.glob("*.yar"):
                self.app.log_activity(f"  [cyan]{rule_file.name}[/cyan]")
        else:
            self.app.log_activity("[red]Rules directory not found.[/red]")

    def handle_clear(self, args: str) -> None:
        """Clear activity log."""
        from textual.widgets import RichLog

        log = self.app.query_one("#activity-log", RichLog)
        log.clear()
        self.app.log_activity("[dim]Activity log cleared.[/dim]")

    def handle_quit(self, args: str) -> None:
        """Exit application."""
        self.app.log_activity("[yellow]Goodbye![/yellow]")
        self.app.exit()

    def start_scan(self, target_path: str) -> None:
        """Start scanning in background."""

        @self.app.work(exclusive=True)
        async def scan():
            dashboard = self.app.query_one("#dashboard", Dashboard)
            dashboard.update_status(f"[bold green]Scanning: {target_path}[/bold green]")

            from malware_scanner.service import MalwareScanner
            from malware_scanner.engine import load_yara_rules

            try:
                rules = await asyncio.to_thread(load_yara_rules, "rules/index.yar")
                scanner = await asyncio.to_thread(
                    lambda: MalwareScanner(rules_path="rules/index.yar")
                )

                import os

                if os.path.isfile(target_path):
                    result = await asyncio.to_thread(scanner.scan_target, target_path)
                    if result:
                        self.app.threat_count += 1
                        self.app.log_activity(
                            f"[red]THREAT DETECTED: {target_path}[/red]"
                        )
                    else:
                        self.app.clean_count += 1
                        self.app.log_activity(f"[green]Clean: {target_path}[/green]")
                    self.app.scan_count += 1
                elif os.path.isdir(target_path):
                    for root, dirs, files in os.walk(target_path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            result = await asyncio.to_thread(
                                scanner.scan_target, filepath
                            )
                            if result:
                                self.app.threat_count += 1
                                self.app.log_activity(f"[red]THREAT: {filepath}[/red]")
                            else:
                                self.app.clean_count += 1
                            self.app.scan_count += 1
                            await asyncio.sleep(0)

                scanner.close()
                dashboard.update_status("[bold]Scan complete.[/bold]")
                self.app.update_stats()
                self.app.log_activity("[green]Scan completed successfully.[/green]")

            except Exception as e:
                dashboard.update_status(f"[bold red]Error: {e}[/bold red]")
                self.app.log_activity(f"[red]Error: {e}[/red]")

        scan()
