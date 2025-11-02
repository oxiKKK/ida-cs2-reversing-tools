"""
CS2 (Counter-Strike 2 / Source 2) Reversing Tools for IDA Pro

A collection of tools to assist with reverse engineering Counter-Strike 2 and
other Source 2 engine binaries.

---------------------------------

Author: oxiKKK 2025
License: MIT
"""

VERSION = "1.0.0"
AUTHOR = "oxiKKK"

from typing import List, Optional

import ida_domain
import idaapi

from PyQt5 import QtCore, QtWidgets


# Import tool modules
from cs2_tools import interface_renamer, convar_renamer


class ToolAction:
    """Base class for tool actions."""

    def __init__(self, name: str, description: str, version: str, hotkey: str = ""):
        self.name = name
        self.description = description
        self.version = version
        self.hotkey = hotkey
        self.action_name = f"cs2tools:{name.lower().replace(' ', '_')}"

    def execute(self, db: ida_domain.Database) -> None:
        """Execute the tool action. Override this in subclasses."""
        raise NotImplementedError("Subclasses must implement execute()")


class InterfaceRenamerAction(ToolAction):
    """Action for renaming interface table entries."""

    def __init__(self):
        super().__init__(
            name="Rename Interface Table",
            description="""\
<p>Automatically rename Source 2 interface pointers based on the interface identifiers.</p>

<p>For example the global variable for interface "VApplication001" gets renamed to "g_pVApplication001".</p>
""",
            version="1.0.0",
            hotkey="Ctrl+Shift+I",
        )

    def execute(self, db: ida_domain.Database) -> None:
        """Execute interface renaming."""
        interface_renamer.run_interface_renamer(db)


class ConVarRenamerAction(ToolAction):
    """Action for renaming ConVar and ConCommand global variables."""

    def __init__(self):
        super().__init__(
            name="Rename ConVars/ConCommands",
            description="""\
<p>Automatically rename ConVar and ConCommand global variables based on their registration names.</p>

<p>Searches for calls to <code>CConVarRef::Register</code> and <code>ConCommand::Register</code>, extracts the name string, and renames the global variable accordingly.</p>

<p>Examples: <code>demo_debug</code>, <code>startmovie</code>, <code>sv_cheats</code>, etc.</p>
""",
            version="1.0.0",
            hotkey="Ctrl+Shift+C",
        )

    def execute(self, db: ida_domain.Database) -> None:
        """Execute ConVar/ConCommand renaming."""
        convar_renamer.run_convar_renamer(db)


class CS2ToolsMenu(QtWidgets.QDialog):
    """Main menu dialog for CS2 Reversing Tools."""

    def __init__(
        self, actions: List[ToolAction], parent: Optional[QtWidgets.QWidget] = None
    ):
        super().__init__(parent)
        self.actions = actions
        self.selected_action: Optional[ToolAction] = None
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the user interface."""
        self.setWindowTitle("CS2 Reversing Tools")
        self.setMinimumWidth(500)

        layout = QtWidgets.QVBoxLayout(self)

        # Header
        header = QtWidgets.QLabel("<h2>CS2 Reversing Tools</h2>")
        header.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(header)

        # Version and Author
        version_info = QtWidgets.QLabel(f"<i>Version {VERSION} by {AUTHOR}</i>")
        version_info.setAlignment(QtCore.Qt.AlignCenter)
        version_info.setStyleSheet("color: #666;")
        layout.addWidget(version_info)

        # Description
        desc = QtWidgets.QLabel(
            "Select a tool to assist with Source 2 binary reverse engineering:"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addSpacing(10)

        # Tool list
        self.tool_list = QtWidgets.QListWidget()
        self.tool_list.itemDoubleClicked.connect(self.on_tool_selected)

        for action in self.actions:
            item = QtWidgets.QListWidgetItem(action.name)
            item.setData(QtCore.Qt.UserRole, action)
            if action.hotkey:
                item.setToolTip(f"{action.description}\nHotkey: {action.hotkey}")
            else:
                item.setToolTip(action.description)
            self.tool_list.addItem(item)

        layout.addWidget(self.tool_list)

        # Description box
        self.desc_box = QtWidgets.QTextEdit()
        self.desc_box.setReadOnly(True)
        self.desc_box.setMaximumHeight(160)
        self.tool_list.currentItemChanged.connect(self.update_description)
        layout.addWidget(self.desc_box)

        # Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        self.run_button = QtWidgets.QPushButton("Execute")
        self.run_button.clicked.connect(self.on_run_clicked)
        self.run_button.setEnabled(False)

        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        btn_layout.addStretch()
        btn_layout.addWidget(self.run_button)
        btn_layout.addWidget(cancel_button)
        layout.addLayout(btn_layout)

        # Select first item by default
        if self.tool_list.count() > 0:
            self.tool_list.setCurrentRow(0)
            self.run_button.setEnabled(True)

    def update_description(
        self,
        current: Optional[QtWidgets.QListWidgetItem],
        previous: Optional[QtWidgets.QListWidgetItem],
    ) -> None:
        """Update the description box when selection changes."""
        if current:
            action = current.data(QtCore.Qt.UserRole)
            desc_text = f"<b>{action.name}</b> <span style='color: #888;'>v{action.version}</span><hr>{action.description}"
            if action.hotkey:
                desc_text += f"<br><br><i>Hotkey: {action.hotkey}</i>"
            self.desc_box.setHtml(desc_text)
            self.run_button.setEnabled(True)
        else:
            self.desc_box.clear()
            self.run_button.setEnabled(False)

    def on_tool_selected(self, item: QtWidgets.QListWidgetItem) -> None:
        """Handle double-click on tool."""
        self.selected_action = item.data(QtCore.Qt.UserRole)
        self.accept()

    def on_run_clicked(self) -> None:
        """Handle Run button click."""
        current = self.tool_list.currentItem()
        if current:
            self.selected_action = current.data(QtCore.Qt.UserRole)
            self.accept()


class CS2ReversingTools(idaapi.plugin_t):
    """Main plugin class for CS2 Reversing Tools."""

    flags = idaapi.PLUGIN_KEEP
    comment = "Tools for reverse engineering Counter-Strike 2 and Source 2 binaries"
    help = "A collection of tools to assist with Source 2 engine reverse engineering"
    wanted_name = "CS2 Reversing Tools"
    wanted_hotkey = "Ctrl+Shift+2"

    def __init__(self):
        super().__init__()
        self.actions: List[ToolAction] = []

    def init(self) -> int:
        """Initialize the plugin."""
        print("[CS2Tools] CS2 Reversing Tools initialized")

        # Register all available tools
        self.actions = [
            InterfaceRenamerAction(),
            ConVarRenamerAction(),
            # Add more tools here as you develop them:
            # SchemaSystemAction(),
            # NetworkVarAnalyzerAction(),
            # etc.
        ]

        # Register hotkey actions
        for action in self.actions:
            self._register_action(action)

        return idaapi.PLUGIN_OK

    def _register_action(self, tool_action: ToolAction) -> None:
        """Register an action with IDA's action system."""
        action_desc = idaapi.action_desc_t(
            tool_action.action_name,
            tool_action.name,
            ActionHandler(tool_action),
            tool_action.hotkey,
            tool_action.description,
            -1,
        )
        idaapi.register_action(action_desc)

    def run(self, arg: int) -> None:
        """Show the main tool selection menu."""
        print("[CS2Tools] Opening CS2 Reversing Tools menu...")

        # Get the database instance
        db: Optional[ida_domain.Database] = ida_domain.Database.open()
        if db is None or not db.is_open():
            print("[CS2Tools] Error: No database is currently open.")
            return

        # Show tool selection dialog
        app = QtWidgets.QApplication.instance()
        if app is None:
            app = QtWidgets.QApplication([])

        dialog = CS2ToolsMenu(self.actions)
        if dialog.exec_() == QtWidgets.QDialog.Accepted and dialog.selected_action:
            try:
                dialog.selected_action.execute(db)
            except Exception as e:
                print(f"[CS2Tools] Error executing {dialog.selected_action.name}: {e}")
                import traceback

                traceback.print_exc()

    def term(self) -> None:
        """Cleanup when plugin is unloaded."""
        # Unregister all actions
        for action in self.actions:
            idaapi.unregister_action(action.action_name)
        print("[CS2Tools] CS2 Reversing Tools terminated")


class ActionHandler(idaapi.action_handler_t):
    """Handler for individual tool actions."""

    def __init__(self, tool_action: ToolAction):
        super().__init__()
        self.tool_action = tool_action

    def activate(self, ctx: idaapi.action_ctx_base_t) -> int:
        """Execute the tool action when triggered via hotkey."""
        db: Optional[ida_domain.Database] = ida_domain.Database.open()
        if db is None or not db.is_open():
            print(f"[CS2Tools] Error: No database is currently open.")
            return 0

        try:
            self.tool_action.execute(db)
        except Exception as e:
            print(f"[CS2Tools] Error executing {self.tool_action.name}: {e}")
            import traceback

            traceback.print_exc()

        return 1

    def update(self, ctx: idaapi.action_ctx_base_t) -> int:
        """Update action availability."""
        return idaapi.AST_ENABLE_ALWAYS


def PLUGIN_ENTRY() -> CS2ReversingTools:
    return CS2ReversingTools()
