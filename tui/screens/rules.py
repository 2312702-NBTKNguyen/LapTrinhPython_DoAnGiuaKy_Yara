"""
Rules screen for browsing YARA rules.

Displays available YARA rules with syntax highlighting
and rule metadata.
"""

from pathlib import Path

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, DirectoryTree, RichLog
from textual.containers import Container, Horizontal


class YaraRuleTree(DirectoryTree):
    """File tree filtered to show only YARA rule files."""

    def filter_paths(self, paths):
        """Show only .yar files."""
        return [
            path for path in paths if path.suffix in (".yar", ".yara") or path.is_dir()
        ]


class RulesScreen(Screen):
    """
    YARA rules browser.

    Shows rule files on left, rule content on right.
    """

    BINDINGS = [
        ("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("[bold]YARA RULES[/bold]", classes="screen-title")

        with Horizontal():
            with Container(id="rules-tree-panel"):
                yield YaraRuleTree(Path("rules"), id="rules-tree")

            with Container(id="rule-content-panel"):
                yield RichLog(id="rule-content", highlight=True, wrap=True)

    def on_directory_tree_file_selected(self, event) -> None:
        """Display selected rule file content."""
        content_log = self.query_one("#rule-content", RichLog)
        content_log.clear()

        try:
            with open(event.path, "r") as f:
                content = f.read()
            content_log.write(content)
        except Exception as e:
            content_log.write(f"Error reading file: {e}")
