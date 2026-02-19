"""
Interface Table Renamer for Source 2 Binaries

Automatically locates and renames interface pointers in Source 2 binaries.
The interface table contains global variables to interfaces such as ICvar,
IEngineClient, etc.

The table usually looks like this:
E0 4F 48 81 01 00 00 00 off_18152D2D0   dq offset aVapplication00 ; "VApplication001"
D0 5A BB 81 01 00 00 00                 dq offset qword_18152D2D0
D0 4F 48 81 01 00 00 00                 dq offset aVenginecvar007 ; "VEngineCvar007"
...

This script locates the table and renames entries to g_pVApplication001,
g_pVEngineCvar007, etc.
"""

from typing import List, Optional, Set, Tuple
import re

import ida_domain
from ida_domain.names import SetNameFlags
from ida_idaapi import ea_t
from PyQt5 import QtWidgets


def msg(s: str) -> None:
    """Print a message with the tool prefix."""
    print(f"[InterfaceRenamer] {s}")


INTERFACE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,127}\d{3,4}$")


def is_probable_interface_name(name: str) -> bool:
    """Return True if a string looks like a Source 2 interface identifier."""
    if not name:
        return False
    if not name.isascii():
        return False
    return INTERFACE_NAME_RE.match(name) is not None


def collect_renames(
    db: ida_domain.Database, start_addr: ea_t, max_entries: int = 128
) -> List[Tuple[ea_t, str]]:
    """Collect renaming information from the interface table.

    Args:
        db: IDA Domain database instance
        start_addr: Starting address of the interface table
        max_entries: Maximum number of entries to process

    Returns:
        List of tuples (address, new_name) for renaming
    """
    renames: List[Tuple[ea_t, str]] = []
    seen_ptrs: Set[ea_t] = set()
    for i in range(max_entries):
        entry = start_addr + i * 0x10
        name_ptr = db.bytes.get_qword_at(entry)
        if name_ptr is None:
            break

        # Validate that name_ptr is a valid address
        if not db.is_valid_ea(name_ptr):
            msg(
                f"Invalid name pointer 0x{name_ptr:X} at entry 0x{entry:X} "
                f"(If this is the last entry, ignore it)"
            )
            break

        ptr = db.bytes.get_qword_at(entry + 0x8)
        if ptr is None:
            break

        # Validate that ptr is a valid address
        if not db.is_valid_ea(ptr):
            msg(f"Invalid interface pointer 0x{ptr:X} at entry 0x{entry + 0x8:X}")
            break

        # Get string at the name pointer
        name = db.bytes.get_cstring_at(name_ptr)
        if not name:
            msg(
                f"Failed to read name at 0x{name_ptr:X} "
                f"(If this is the last entry, ignore it)"
            )
            break

        if not is_probable_interface_name(name):
            msg(
                f"Stopping at 0x{entry:X}: '{name}' does not look like an interface name"
            )
            break

        if ptr in seen_ptrs:
            msg(
                f"Stopping at 0x{entry:X}: duplicate interface pointer 0x{ptr:X} "
                f"(likely end of table)"
            )
            break

        seen_ptrs.add(ptr)
        var_name = f"g_p{name}"
        renames.append((ptr, var_name))
    return renames


def find_interface_table(db: ida_domain.Database, string_name: str) -> Optional[ea_t]:
    """Locate the start of the interface table.

    Strategy when multiple occurrences exist:
    - Enumerate all string items equal to `string_name`.
    - For each xref to that string, verify that the xref address looks like a
      table entry: [qword -> C-string][qword -> pointer], and that the next
      entry (ea+0x10) also starts with a valid C-string (usually begins with 'V').
    - If valid, backtrack in -0x10 steps to the first valid entry to get table start.
    - Prefer the candidate that yields the longest forward run of valid entries.

    Args:
        db: IDA Domain database instance
        string_name: Name of the string to search for (e.g., "VApplication001")

    Returns:
        Address of the interface table start, or None if not found
    """

    def read_c_string(ea: ea_t) -> Optional[str]:
        if not ea or not db.is_valid_ea(ea):
            return None
        return db.bytes.get_cstring_at(ea)

    def is_valid_entry(ea: ea_t) -> bool:
        try:
            name_ptr = db.bytes.get_qword_at(ea)
            if name_ptr is None or name_ptr == 0:
                return False
            name = read_c_string(name_ptr)
            if not name or not is_probable_interface_name(name):
                return False
            ptr = db.bytes.get_qword_at(ea + 0x8)
            if ptr is None or ptr == 0 or not db.is_valid_ea(ptr):
                return False
            return True
        except Exception:
            return False

    def looks_like_table_anchor(ea: ea_t) -> bool:
        """Stricter check used for initial anchor validation."""
        if not is_valid_entry(ea):
            return False
        # Also check that the next entry looks valid and has a plausible interface name
        next_name_ptr = db.bytes.get_qword_at(ea + 0x10)
        if next_name_ptr is None:
            return False
        next_str = read_c_string(next_name_ptr)
        if not next_str or not is_probable_interface_name(next_str):
            return False
        return True

    def backtrack_start(ea: ea_t) -> ea_t:
        cur = ea
        while True:
            prev = cur - 0x10
            if prev <= 0:
                break
            if not is_valid_entry(prev):
                break
            cur = prev
        return cur

    def forward_count(ea: ea_t, max_check: int = 1024) -> int:
        cnt = 0
        cur = ea
        for _ in range(max_check):
            if not is_valid_entry(cur):
                break
            cnt += 1
            cur += 0x10
        return cnt

    best: Optional[ea_t] = None
    best_count: int = 0

    # Search for the string in the database
    for string_item in db.strings:
        if str(string_item) != string_name:
            continue

        # Get xrefs to this string
        for xref in db.xrefs.to_ea(string_item.address):
            ea = xref.from_ea

            # Ensure the qword at xref address actually equals the string EA (data ref),
            # which filters out code refs and unrelated uses.
            try:
                qword_val = db.bytes.get_qword_at(ea)
                if qword_val is None or qword_val != string_item.address:
                    continue
            except Exception:
                continue

            if not looks_like_table_anchor(ea):
                # Not a proper table context
                continue

            start = backtrack_start(ea)
            cnt = forward_count(start)
            msg(
                f"Candidate table at {hex(start)} (backtracked from {hex(ea)}), "
                f"entries={cnt}"
            )
            if cnt > best_count:
                best = start
                best_count = cnt

    if best is not None:
        msg(f"Selected interface table at {hex(best)} with {best_count} entries (est).")
        return best

    return None


class RenameDialog(QtWidgets.QDialog):
    """Dialog to confirm interface renaming."""

    def __init__(
        self,
        count: int,
        renames: List[Tuple[ea_t, str]],
        parent: Optional[QtWidgets.QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Rename Interface Pointers")
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel(f"Rename {count} interface pointer(s)?"))

        # Multi-line text box with scrollbar showing the renames
        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlainText(
            "\n".join(f"0x{ptr:X} -> {var_name}" for ptr, var_name in renames)
        )
        layout.addWidget(self.text_edit)

        btn_layout = QtWidgets.QHBoxLayout()
        self.yes_button = QtWidgets.QPushButton("Rename All")
        self.no_button = QtWidgets.QPushButton("Cancel")
        btn_layout.addWidget(self.yes_button)
        btn_layout.addWidget(self.no_button)
        layout.addLayout(btn_layout)
        self.yes_button.clicked.connect(self.accept)
        self.no_button.clicked.connect(self.reject)


def run_interface_renamer(db: ida_domain.Database) -> None:
    """Main entry point for the interface renamer tool.

    Args:
        db: IDA Domain database instance
    """
    msg("Starting interface table search...")

    # Find the interface table
    table_entry = find_interface_table(db, "VApplication001")
    if table_entry is None:
        msg("Interface table not found.")
        QtWidgets.QMessageBox.warning(
            None,
            "Interface Table Not Found",
            "Could not locate the Source 2 interface table.\n\n"
            "Make sure you're analyzing a Source 2 binary with an interface table.",
        )
        return

    # Collect all renames
    renames = collect_renames(db, table_entry)
    if not renames:
        msg("No interfaces found to rename.")
        QtWidgets.QMessageBox.information(
            None,
            "No Interfaces Found",
            "The interface table was found but no valid entries could be parsed.",
        )
        return

    msg(f"Found {len(renames)} interface(s) to rename")

    # Show confirmation dialog
    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication([])

    dialog = RenameDialog(len(renames), renames)
    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        success_count = 0
        fail_count = 0

        for ptr, var_name in renames:
            if db.names.set_name(ptr, var_name, SetNameFlags.CHECK):
                msg(f"Renamed 0x{ptr:X} to {var_name}")
                success_count += 1
            else:
                msg(f"Error: Failed to rename 0x{ptr:X} to {var_name}")
                fail_count += 1

        msg(f"Renaming complete: {success_count} succeeded, {fail_count} failed")

        QtWidgets.QMessageBox.information(
            None,
            "Renaming Complete",
            f"Successfully renamed {success_count} interface pointer(s).\n"
            + (f"{fail_count} rename(s) failed." if fail_count > 0 else ""),
        )
    else:
        msg("Operation canceled by user")
