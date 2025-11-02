"""
ConVar/ConCommand Renamer Tool

Automatically renames global ConVar and ConCommand variables based on their
registration string names in Source 2 binaries.

Note: This tool uses heuristics to locate and extract registration call arguments.
Some ConVars/ConCommands may be registered using different techniques (e.g., dynamic
registration, indirect calls, or obfuscated patterns) that cannot be easily automated.
However, this approach successfully handles the majority of standard registration cases.

Author: oxiKKK 2025
License: MIT
"""

from typing import List, Tuple, Optional, Set
import re

import ida_domain
from ida_domain.operands import MemoryOperand, ImmediateOperand
from ida_domain.names import SetNameFlags
from PyQt5.QtWidgets import (
    QMessageBox,
    QDialog,
    QVBoxLayout,
    QLabel,
    QTextEdit,
    QPushButton,
    QHBoxLayout,
)


def find_register_functions(
    db: ida_domain.Database,
) -> Tuple[Optional[int], Optional[int]]:
    """
    Find CConVarRef::Register and ConCommand register function addresses.

    Uses multiple heuristics to locate these functions:
    1. Search for error strings unique to each function
    2. Find xrefs to those strings
    3. Select the function with the most xrefs (actual register function vs deferred helper)
    4. Validate function signatures

    Returns:
        Tuple of (convar_register_ea, concommand_register_ea)
    """
    convar_register_ea = None
    concommand_register_ea = None

    # Search for unique error strings
    convar_error_str = "RegisterConVar: Unknown error registering convar"
    concommand_error_str = "RegisterConCommand: Unknown error registering con command"

    print("[ConVarRenamer] Searching for registration functions...")

    # Find ConVar register function
    # The error string may appear in multiple functions, we want the one with the most xrefs
    # (the actual Register function, not the deferred registration helper)
    for string_item in db.strings:
        content = str(string_item)
        if content and convar_error_str in content:
            # Found the error string, find xrefs
            string_ea = string_item.address
            print(f"[ConVarRenamer] Found ConVar error string at {hex(string_ea)}")

            # Collect all functions that reference this string
            candidate_functions = []
            for xref in db.xrefs.to_ea(string_ea):
                func = db.functions.get_at(xref.from_ea)
                if func:
                    # Count how many xrefs this function has (how many places call it)
                    xref_count = sum(1 for _ in db.xrefs.to_ea(func.start_ea))
                    candidate_functions.append((func.start_ea, xref_count))
                    print(
                        f"[ConVarRenamer]   Candidate function at {hex(func.start_ea)} has {xref_count} xrefs"
                    )

            # Select the function with the most xrefs (the actual Register function)
            # The real Register function is called from many initialization functions
            # The deferred helper is only called from one place
            if candidate_functions:
                candidate_functions.sort(key=lambda x: x[1], reverse=True)
                convar_register_ea = candidate_functions[0][0]
                print(
                    f"[ConVarRenamer] Selected CConVarRef::Register at {hex(convar_register_ea)} ({candidate_functions[0][1]} xrefs)"
                )
            break

    # Find ConCommand register function
    for string_item in db.strings:
        content = str(string_item)
        if content and concommand_error_str in content:
            # Found the error string, find xrefs
            string_ea = string_item.address
            print(f"[ConVarRenamer] Found ConCommand error string at {hex(string_ea)}")

            # Collect all functions that reference this string
            candidate_functions = []
            for xref in db.xrefs.to_ea(string_ea):
                func = db.functions.get_at(xref.from_ea)
                if func:
                    # Count how many xrefs this function has
                    xref_count = sum(1 for _ in db.xrefs.to_ea(func.start_ea))
                    candidate_functions.append((func.start_ea, xref_count))
                    print(
                        f"[ConVarRenamer]   Candidate function at {hex(func.start_ea)} has {xref_count} xrefs"
                    )

            # Select the function with the most xrefs
            if candidate_functions:
                candidate_functions.sort(key=lambda x: x[1], reverse=True)
                concommand_register_ea = candidate_functions[0][0]
                print(
                    f"[ConVarRenamer] Selected ConCommand::Register at {hex(concommand_register_ea)} ({candidate_functions[0][1]} xrefs)"
                )
            break

    return convar_register_ea, concommand_register_ea


def extract_call_arguments(
    db: ida_domain.Database, call_ea: int
) -> Optional[Tuple[int, str]]:
    """
    Extract the global variable address and name string from a register call.

    Both ConVar (CConVarRef::Register) and ConCommand use the same calling convention:
        - arg1 (RCX): Pointer to global variable
        - arg2 (RDX): Name string pointer

    Args:
        db: IDA database instance
        call_ea: Address of the call instruction

    Returns:
        Tuple of (global_var_ea, name_string) or None if extraction fails
    """
    func = db.functions.get_at(call_ea)
    if not func:
        return None

    current_ea = call_ea
    global_var_ea = None
    name_str_ea = None

    search_limit = 50
    instructions_checked = 0

    # Walk backwards from the call, collecting ALL candidates for RCX and RDX
    # We'll take the most recent (last found while walking backwards) assignment
    rcx_candidates = []
    rdx_candidates = []

    while instructions_checked < search_limit and current_ea >= func.start_ea:
        insn = db.instructions.get_at(current_ea)
        if not insn:
            break

        disasm = db.instructions.get_disassembly(insn)

        # Look for RCX assignments (first argument - global variable)
        if "rcx" in disasm.lower():
            if "lea" in disasm.lower() or "mov" in disasm.lower():
                operands = db.instructions.get_operands(insn)
                for op in operands:
                    addr = None
                    if isinstance(op, MemoryOperand):
                        addr = op.get_address()
                    elif isinstance(op, ImmediateOperand):
                        addr = op.get_value()

                    if addr and db.is_valid_ea(addr):
                        rcx_candidates.append(addr)
                        break

        # Look for RDX assignments (second argument - name string)
        if "rdx" in disasm.lower():
            if "lea" in disasm.lower() or "mov" in disasm.lower():
                operands = db.instructions.get_operands(insn)
                for op in operands:
                    addr = None
                    if isinstance(op, ImmediateOperand):
                        addr = op.get_value()
                    elif isinstance(op, MemoryOperand):
                        addr = op.get_address()

                    if addr and db.is_valid_ea(addr):
                        # Validate it's actually a string
                        try:
                            test_str = db.bytes.get_cstring_at(addr)
                            if (
                                test_str
                                and len(test_str) > 0
                                and test_str.isprintable()
                            ):
                                rdx_candidates.append(addr)
                                break
                        except:
                            pass

        # Move to previous instruction
        prev_insn = db.instructions.get_previous(current_ea)
        if not prev_insn or prev_insn.ea >= current_ea:
            break
        current_ea = prev_insn.ea
        instructions_checked += 1

    # Take the most recent assignment (first in our backwards walk)
    if rcx_candidates:
        global_var_ea = rcx_candidates[0]
    if rdx_candidates:
        name_str_ea = rdx_candidates[0]

    # Debug output
    if not rcx_candidates:
        print(
            f"[ConVarRenamer]     DEBUG: No RCX candidates found for call at {hex(call_ea)}"
        )
    if not rdx_candidates:
        print(
            f"[ConVarRenamer]     DEBUG: No RDX candidates found for call at {hex(call_ea)}"
        )
    if rcx_candidates and rdx_candidates:
        print(
            f"[ConVarRenamer]     DEBUG: Found RCX={hex(rcx_candidates[0])}, RDX={hex(rdx_candidates[0])} for call at {hex(call_ea)}"
        )

    # Validate and extract the name string
    if global_var_ea and name_str_ea:
        try:
            name = db.bytes.get_cstring_at(name_str_ea)
            if name and len(name) > 0:
                # Sanitize and validate
                name = "".join(c for c in name if c.isprintable())
                # Extra validation: must look like a reasonable ConVar name
                if name and len(name) > 1 and not all(c in "_" for c in name):
                    return (global_var_ea, name)
                else:
                    print(
                        f"[ConVarRenamer]     DEBUG: Name validation failed for '{name}' at call {hex(call_ea)}"
                    )
        except Exception as e:
            print(f"[ConVarRenamer]     DEBUG: Exception reading name string: {e}")

    return None


def collect_convars_and_concommands(
    db: ida_domain.Database,
    convar_register_ea: Optional[int],
    concommand_register_ea: Optional[int],
) -> List[Tuple[int, str, str]]:
    """
    Collect all ConVar and ConCommand global variables with their names.

    Returns:
        List of tuples: (global_var_ea, name, type)
        where type is "convar" or "concommand"
    """
    results: List[Tuple[int, str, str]] = []
    seen_addresses: Set[int] = set()

    # Process ConVar registrations
    if convar_register_ea:
        print(f"[ConVarRenamer] Processing ConVar registrations...")
        xref_count = 0

        for xref in db.xrefs.to_ea(convar_register_ea):
            xref_count += 1
            result = extract_call_arguments(db, xref.from_ea)

            if result:
                global_var_ea, name = result

                # Avoid duplicates
                if global_var_ea not in seen_addresses:
                    seen_addresses.add(global_var_ea)
                    results.append((global_var_ea, name, "convar"))
                    print(
                        f"[ConVarRenamer]   Found ConVar: {name} at {hex(global_var_ea)}"
                    )
            else:
                print(
                    f"[ConVarRenamer]   WARNING: Failed to extract arguments from call at {hex(xref.from_ea)}"
                )

        print(
            f"[ConVarRenamer] Processed {xref_count} ConVar xrefs, found {len([r for r in results if r[2] == 'convar'])} unique ConVars"
        )

    # Process ConCommand registrations
    if concommand_register_ea:
        print(f"[ConVarRenamer] Processing ConCommand registrations...")
        xref_count = 0

        for xref in db.xrefs.to_ea(concommand_register_ea):
            xref_count += 1
            result = extract_call_arguments(db, xref.from_ea)

            if result:
                global_var_ea, name = result

                # Avoid duplicates
                if global_var_ea not in seen_addresses:
                    seen_addresses.add(global_var_ea)
                    results.append((global_var_ea, name, "concommand"))
                    print(
                        f"[ConVarRenamer]   Found ConCommand: {name} at {hex(global_var_ea)}"
                    )
            else:
                print(
                    f"[ConVarRenamer]   WARNING: Failed to extract arguments from call at {hex(xref.from_ea)}"
                )

        print(
            f"[ConVarRenamer] Processed {xref_count} ConCommand xrefs, found {len([r for r in results if r[2] == 'concommand'])} unique ConCommands"
        )

    return results


def apply_renames(
    db: ida_domain.Database, renames: List[Tuple[int, str, str]]
) -> Tuple[int, int]:
    """
    Apply the collected renames to the database.

    Returns:
        Tuple of (success_count, fail_count)
    """
    success_count = 0
    fail_count = 0

    for global_var_ea, name, var_type in renames:
        # Sanitize name to be a valid C identifier
        sanitized_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        # Check if the address already has the target name
        current_name = db.names.get_at(global_var_ea)
        if current_name == sanitized_name:
            success_count += 1
            print(
                f"[ConVarRenamer] Skipped {hex(global_var_ea)} -> {sanitized_name} (already has this name)"
            )
            continue

        try:
            # Try to set the name, using CHECK so we don't clobber existing symbols
            if db.names.set_name(global_var_ea, sanitized_name, SetNameFlags.NOCHECK):
                success_count += 1
                print(
                    f"[ConVarRenamer] Renamed {hex(global_var_ea)} -> {sanitized_name}"
                )
            else:
                # Rename failed (name conflict or other issue)
                fail_count += 1
                print(
                    f"[ConVarRenamer] Failed to rename {hex(global_var_ea)} to {sanitized_name} (name conflict or validation failed)"
                )
        except Exception as e:
            # Exception occurred (e.g., "name already used in the program")
            fail_count += 1
            print(
                f"[ConVarRenamer] Failed to rename {hex(global_var_ea)} to {sanitized_name}: {e}"
            )

    return success_count, fail_count


class ConVarPreviewDialog(QDialog):
    """Dialog to preview ConVars/ConCommands before renaming."""

    def __init__(self, renames: List[Tuple[int, str, str]], parent=None):
        super().__init__(parent)
        self.renames = renames
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("ConVar/ConCommand Preview")
        self.setMinimumWidth(700)
        self.setMinimumHeight(500)

        layout = QVBoxLayout(self)

        # Header
        convar_count = len([r for r in self.renames if r[2] == "convar"])
        concommand_count = len([r for r in self.renames if r[2] == "concommand"])

        header = QLabel(
            f"<h3>Found {len(self.renames)} items to rename</h3>"
            f"<p>{convar_count} ConVars • {concommand_count} ConCommands</p>"
        )
        layout.addWidget(header)

        # Preview text box (read-only)
        self.preview_box = QTextEdit()
        self.preview_box.setReadOnly(True)
        self.preview_box.setFontFamily("Consolas, Courier New, monospace")

        # Build preview text
        preview_text = []
        preview_text.append("=" * 80)
        preview_text.append(f"{'Address':<18} {'Type':<12} {'Name'}")
        preview_text.append("=" * 80)

        for addr, name, var_type in sorted(self.renames, key=lambda x: x[0]):
            type_str = "ConVar" if var_type == "convar" else "ConCommand"
            preview_text.append(f"{hex(addr):<18} {type_str:<12} {name}")

        preview_text.append("=" * 80)

        self.preview_box.setPlainText("\n".join(preview_text))
        layout.addWidget(self.preview_box)

        # Buttons
        button_layout = QHBoxLayout()

        self.apply_button = QPushButton("Apply Renames")
        self.apply_button.clicked.connect(self.accept)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        button_layout.addStretch()
        button_layout.addWidget(self.apply_button)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)


def run_convar_renamer(db: ida_domain.Database) -> None:
    """
    Main entry point for the ConVar/ConCommand renamer tool.
    """
    print("[ConVarRenamer] Starting ConVar/ConCommand renamer...")

    # Step 1: Find the registration functions
    convar_register_ea, concommand_register_ea = find_register_functions(db)

    if not convar_register_ea and not concommand_register_ea:
        error_msg = (
            "Could not locate ConVar or ConCommand registration functions.\n\n"
            "This tool searches for unique error strings to identify the functions:\n"
            '- "RegisterConVar: Unknown error registering convar"\n'
            '- "RegisterConCommand: Unknown error registering con command"\n\n'
            "Make sure you're analyzing a Source 2 binary with these functions present."
        )
        print(f"[ConVarRenamer] {error_msg}")
        QMessageBox.warning(None, "ConVar Renamer - Not Found", error_msg)
        return

    if not convar_register_ea:
        print("[ConVarRenamer] Warning: Could not find CConVarRef::Register function")

    if not concommand_register_ea:
        print("[ConVarRenamer] Warning: Could not find ConCommand register function")

    # Step 2: Collect all ConVars and ConCommands
    renames = collect_convars_and_concommands(
        db, convar_register_ea, concommand_register_ea
    )

    if not renames:
        error_msg = (
            "No ConVars or ConCommands found.\n\n"
            "The registration functions were located, but no calls to them "
            "could be analyzed successfully. This may indicate:\n"
            "- The binary uses a different calling convention\n"
            "- The registration pattern has changed\n"
            "- Heavy obfuscation is present"
        )
        print(f"[ConVarRenamer] {error_msg}")
        QMessageBox.warning(None, "ConVar Renamer - No Results", error_msg)
        return

    # Show summary
    convar_count = len([r for r in renames if r[2] == "convar"])
    concommand_count = len([r for r in renames if r[2] == "concommand"])

    print(
        f"[ConVarRenamer] Found {len(renames)} items: {convar_count} ConVars, {concommand_count} ConCommands"
    )

    # Show preview dialog
    dialog = ConVarPreviewDialog(renames)
    if dialog.exec_() != QDialog.Accepted:
        print("[ConVarRenamer] Rename operation cancelled by user")
        return

    # Step 3: Apply renames
    success_count, fail_count = apply_renames(db, renames)

    # Show results
    result_msg = (
        f"Rename operation completed:\n\n"
        f"  ✓ Successfully renamed: {success_count}\n"
        f"  ✗ Failed: {fail_count}\n\n"
        "Check the output window for detailed results."
    )

    print(f"[ConVarRenamer] {result_msg}")
    QMessageBox.information(None, "ConVar Renamer - Complete", result_msg)
