"""
Template for creating new CS2 reversing tools.

Copy this file and implement your tool following the structure below.
"""

from typing import Optional

import ida_domain
from ida_idaapi import ea_t
from PyQt5 import QtWidgets


def msg(s: str) -> None:
    """Print a message with the tool prefix."""
    print(f"[YourTool] {s}")


def run_your_tool(db: ida_domain.Database) -> None:
    """Main entry point for your tool.

    Args:
        db: IDA Domain database instance
    """
    msg("Starting your tool...")

    try:
        # Your tool logic goes here
        # Example operations:
        # - Iterate over functions: for func in db.functions:
        # - Find strings: for string in db.strings:
        # - Analyze xrefs: for xref in db.xrefs.to_ea(address):
        # - Set names: db.names.set_name(address, name)
        # - Get/set comments: db.comments.set(address, "comment")

        # Show results to user
        QtWidgets.QMessageBox.information(
            None, "Tool Complete", "Your tool completed successfully!"
        )

        msg("Tool completed successfully")

    except Exception as e:
        msg(f"Error: {e}")
        QtWidgets.QMessageBox.critical(
            None, "Tool Error", f"An error occurred:\n{str(e)}"
        )
        raise


# Example: Schema System Analyzer
def run_schema_analyzer(db: ida_domain.Database) -> None:
    """Analyze and document the Source 2 schema system.

    This could identify schema classes, their fields, and network variables.
    """
    msg("Analyzing schema system...")
    # Implementation here
    pass


# Example: Network Variable Analyzer
def run_netvar_analyzer(db: ida_domain.Database) -> None:
    """Analyze network variables (netvars) in the binary.

    This could identify networked properties and their offsets.
    """
    msg("Analyzing network variables...")
    # Implementation here
    pass


# Example: Virtual Table Analyzer
def run_vtable_analyzer(db: ida_domain.Database) -> None:
    """Analyze and label virtual tables.

    This could identify C++ vtables and label their methods.
    """
    msg("Analyzing virtual tables...")
    # Implementation here
    pass
