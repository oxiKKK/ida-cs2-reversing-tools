"""
Pseudocode Dumper for functions marked as decompiled.

This tool exports pseudocode only for functions marked with IDA's
"Mark/unmark as decompiled" command.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple
import re

import ida_diskio
import ida_domain
import ida_nalt
from PyQt5.QtWidgets import QFileDialog, QMessageBox


DEFAULT_MARK_BGCOLOR = 0x50351B
MARK_COLOR_RE = re.compile(r"^\s*MARK_BGCOLOR\s*=\s*(0x[0-9A-Fa-f]+|\d+)")


def _log(message: str) -> None:
    print(f"[PseudocodeDumper] {message}")


def _resolve_mark_bgcolor() -> int:
    """Resolve MARK_BGCOLOR from hexrays.cfg, fallback to known default."""
    try:
        cfg_path = ida_diskio.getsysfile("hexrays.cfg", ida_diskio.CFG_SUBDIR)
        if not cfg_path:
            return DEFAULT_MARK_BGCOLOR

        path = Path(cfg_path)
        if not path.exists():
            return DEFAULT_MARK_BGCOLOR

        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = MARK_COLOR_RE.match(line)
                if not match:
                    continue
                value = match.group(1)
                return int(value, 0)
    except Exception as exc:
        _log(f"Failed to read hexrays.cfg MARK_BGCOLOR: {exc}")

    return DEFAULT_MARK_BGCOLOR


def _get_marked_functions(
    db: ida_domain.Database, mark_color: int
) -> List[Tuple[int, str, str]]:
    """Collect functions marked as decompiled using function background color."""
    marked: List[Tuple[int, str, str]] = []

    for func in db.functions:
        if func is None:
            continue

        if int(func.color) != int(mark_color):
            continue

        name = db.functions.get_name(func) or f"sub_{func.start_ea:X}"
        signature = db.functions.get_signature(func) or ""
        marked.append((func.start_ea, name, signature))

    marked.sort(key=lambda x: x[0])
    return marked


def _ask_output_path() -> Optional[str]:
    """Prompt user for destination output file with smart default name."""
    default_name = "marked_decompiled_pseudocode.c"

    try:
        root_filename = ida_nalt.get_root_filename() or ""
        stem = Path(root_filename).stem.strip()
        if stem:
            default_name = f"{stem}_marked_decompiled_pseudocode.c"
    except Exception as exc:
        _log(f"Failed to resolve input filename for default output name: {exc}")

    default_path = default_name
    try:
        input_path = ida_nalt.get_input_file_path() or ""
        if input_path:
            input_dir = Path(input_path).parent
            if str(input_dir):
                default_path = str(input_dir / default_name)
    except Exception:
        # Keep default output name if full input path is unavailable.
        pass

    file_path, _ = QFileDialog.getSaveFileName(
        None,
        "Dump pseudocode of marked functions",
        default_path,
        "C files (*.c);;Text files (*.txt);;All files (*)",
    )
    if not file_path:
        return None
    return file_path


def _format_function_block(ea: int, name: str, signature: str, lines: List[str]) -> str:
    sig_line = signature if signature else "<signature unavailable>"
    header = (
        f"/* {'=' * 76}\n"
        f" * Function: {name}\n"
        f" * Address : 0x{ea:X}\n"
        f" * Signature: {sig_line}\n"
        f" {'=' * 76} */\n"
    )
    body = "\n".join(lines) if lines else "/* <no pseudocode lines> */"
    return f"{header}{body}\n\n"


def run_marked_pseudocode_dumper(db: ida_domain.Database) -> None:
    """Dump pseudocode of functions marked as decompiled to a file."""
    _log("Starting pseudocode dump for marked functions...")

    mark_color = _resolve_mark_bgcolor()
    _log(f"Using MARK_BGCOLOR = 0x{mark_color:06X}")

    marked_functions = _get_marked_functions(db, mark_color)
    if not marked_functions:
        msg = (
            "No functions marked as decompiled were found.\n\n"
            "This tool only exports functions marked with the decompiler's "
            "'Mark/unmark as decompiled' command."
        )
        _log(msg)
        QMessageBox.information(None, "Pseudocode Dumper", msg)
        return

    output_path = _ask_output_path()
    if not output_path:
        _log("Dump cancelled by user.")
        return

    success_count = 0
    failed: List[Tuple[int, str, str]] = []
    blocks: List[str] = []

    for ea, name, signature in marked_functions:
        try:
            func = db.functions.get_at(ea)
            if not func:
                raise RuntimeError("Function no longer exists")
            pseudocode_lines = db.functions.get_pseudocode(func, remove_tags=True)
            blocks.append(_format_function_block(ea, name, signature, pseudocode_lines))
            success_count += 1
        except Exception as exc:
            failed.append((ea, name, str(exc)))
            _log(f"Failed to decompile {name} @ 0x{ea:X}: {exc}")

    try:
        with open(output_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("/* Pseudocode dump of functions marked as decompiled */\n")
            f.write(f"/* MARK_BGCOLOR: 0x{mark_color:06X} */\n")
            f.write(
                f"/* Marked functions: {len(marked_functions)}, successfully dumped: {success_count}, failures: {len(failed)} */\n\n"
            )

            for block in blocks:
                f.write(block)

            if failed:
                f.write("/* Failed to decompile functions */\n")
                for ea, name, reason in failed:
                    f.write(f"/* 0x{ea:X} {name}: {reason} */\n")
    except Exception as exc:
        error_msg = f"Failed to write output file:\n{output_path}\n\n{exc}"
        _log(error_msg)
        QMessageBox.critical(None, "Pseudocode Dumper - Write Error", error_msg)
        return

    result_msg = (
        f"Pseudocode dump complete.\n\n"
        f"Marked functions: {len(marked_functions)}\n"
        f"Successfully dumped: {success_count}\n"
        f"Failed to decompile: {len(failed)}\n\n"
        f"Output file:\n{output_path}"
    )
    _log(result_msg)
    QMessageBox.information(None, "Pseudocode Dumper - Complete", result_msg)
