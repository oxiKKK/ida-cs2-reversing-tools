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

from collections import deque
from typing import Deque, Dict, List, Optional, Set, Tuple
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


def _log(verbose: bool, message: str) -> None:
    """Print a message only when verbose output is enabled."""
    if verbose:
        print(message)


def _find_function_candidates_by_error_string(
    db: ida_domain.Database,
    error_substring: str,
    item_label: str,
    selected_label: str,
) -> Tuple[Optional[int], List[int]]:
    """Find candidate register functions by searching for a known error string."""
    for string_item in db.strings:
        content = str(string_item)
        if not content or error_substring not in content:
            continue

        string_ea = string_item.address
        print(f"[ConVarRenamer] Found {item_label} error string at {hex(string_ea)}")

        candidate_map: Dict[int, int] = {}
        for xref in db.xrefs.to_ea(string_ea):
            func = db.functions.get_at(xref.from_ea)
            if not func:
                continue

            xref_count = sum(1 for _ in db.xrefs.to_ea(func.start_ea))
            prev_count = candidate_map.get(func.start_ea)
            if prev_count is None or xref_count > prev_count:
                candidate_map[func.start_ea] = xref_count

        ranked_candidates = sorted(
            candidate_map.items(), key=lambda x: x[1], reverse=True
        )

        candidates: List[int] = []
        for start_ea, xref_count in ranked_candidates:
            print(
                f"[ConVarRenamer]   Candidate function at {hex(start_ea)} has {xref_count} xrefs"
            )
            candidates.append(start_ea)

        selected = ranked_candidates[0][0] if ranked_candidates else None
        if selected is not None:
            print(
                f"[ConVarRenamer] Selected {selected_label} at {hex(selected)} ({ranked_candidates[0][1]} xrefs)"
            )

        return selected, candidates

    return None, []


def find_register_functions(
    db: ida_domain.Database,
) -> Tuple[Optional[int], Optional[int], List[int], List[int]]:
    """
    Find CConVarRef::Register and ConCommand register function addresses.

    Uses multiple heuristics to locate these functions:
    1. Search for error strings unique to each function
    2. Find xrefs to those strings
    3. Select the function with the most xrefs (actual register function vs deferred helper)
    4. Validate function signatures

    Returns:
        Tuple of:
            (selected_convar_register_ea,
             selected_concommand_register_ea,
             all_convar_candidates,
             all_concommand_candidates)
    """
    convar_error_str = "RegisterConVar: Unknown error registering convar"
    concommand_error_str = "RegisterConCommand: Unknown error registering con command"

    print("[ConVarRenamer] Searching for registration functions...")

    convar_register_ea, convar_candidates = _find_function_candidates_by_error_string(
        db,
        convar_error_str,
        item_label="ConVar",
        selected_label="CConVarRef::Register",
    )

    (
        concommand_register_ea,
        concommand_candidates,
    ) = _find_function_candidates_by_error_string(
        db,
        concommand_error_str,
        item_label="ConCommand",
        selected_label="ConCommand::Register",
    )

    return (
        convar_register_ea,
        concommand_register_ea,
        convar_candidates,
        concommand_candidates,
    )


REGISTER_ALIASES = {
    "rcx": ("rcx", "ecx"),
    "rdx": ("rdx", "edx"),
    "rdi": ("rdi", "edi"),
    "rsi": ("rsi", "esi"),
}

REGISTER_NORMALIZATION = {
    "rax": "rax",
    "eax": "rax",
    "rbx": "rbx",
    "ebx": "rbx",
    "rcx": "rcx",
    "ecx": "rcx",
    "rdx": "rdx",
    "edx": "rdx",
    "rsi": "rsi",
    "esi": "rsi",
    "rdi": "rdi",
    "edi": "rdi",
    "rbp": "rbp",
    "ebp": "rbp",
    "rsp": "rsp",
    "esp": "rsp",
    "r8": "r8",
    "r8d": "r8",
    "r9": "r9",
    "r9d": "r9",
    "r10": "r10",
    "r10d": "r10",
    "r11": "r11",
    "r11d": "r11",
    "r12": "r12",
    "r12d": "r12",
    "r13": "r13",
    "r13d": "r13",
    "r14": "r14",
    "r14d": "r14",
    "r15": "r15",
    "r15d": "r15",
}

# Try likely calling convention register pairs in order.
# Windows x64: arg1=rcx, arg2=rdx
# SysV x64 (common Linux): arg1=rdi, arg2=rsi
# SysV x64 member-call style: this=rdi, arg1=rsi, arg2=rdx
ARG_REGISTER_PAIRS = [
    ("rcx", "rdx", "win64"),
    ("rdi", "rsi", "sysv"),
    ("rsi", "rdx", "sysv-member"),
]

CONSOLE_NAME_RE = re.compile(r"^[A-Za-z0-9_+\-.:/]{2,128}$")


DESCRIPTOR_PATTERNS = [
    # Linux/SysV descriptor-based ConVar registration
    {"name": "convar-desc-rdi", "arg_reg": "rdi", "name_off": 0x0, "global_off": 0x90},
    # Linux/SysV descriptor-based ConCommand registration
    {
        "name": "concommand-desc-rdi",
        "arg_reg": "rdi",
        "name_off": 0x0,
        "global_off": 0x38,
    },
    # Windows-style variants if compiler uses RCX as first arg
    {"name": "convar-desc-rcx", "arg_reg": "rcx", "name_off": 0x0, "global_off": 0x90},
    {
        "name": "concommand-desc-rcx",
        "arg_reg": "rcx",
        "name_off": 0x0,
        "global_off": 0x38,
    },
]


def _normalize_register_token(token: str) -> Optional[str]:
    """Normalize register token (e.g., ecx->rcx) for value propagation."""
    if not token:
        return None

    reg = token.lower().strip()
    reg = reg.replace("ptr", "").replace("short", "").replace("near", "")
    reg = reg.replace("far", "").replace("cs:", "").replace("ds:", "")
    reg = reg.replace("ss:", "").replace(",", "").strip()

    # Keep plain register tokens only.
    if "[" in reg or "]" in reg:
        return None
    return REGISTER_NORMALIZATION.get(reg)


def _parse_stack_offset_expr(expr: str) -> Optional[int]:
    """Parse IDA stack offset expressions like -0C0h, +var_70, +28h+var_20."""
    if not expr:
        return 0

    text = expr.lower().replace(" ", "")
    if not text:
        return 0

    # Normalize to sequence of signed terms.
    if text[0] not in "+-":
        text = "+" + text

    total = 0
    pos = 0
    while pos < len(text):
        sign = 1 if text[pos] == "+" else -1
        pos += 1
        start = pos
        while pos < len(text) and text[pos] not in "+-":
            pos += 1
        term = text[start:pos]
        if not term:
            return None

        value: Optional[int]
        value = None
        if term.startswith("var_"):
            # IDA's var_XX convention usually means negative frame offset.
            try:
                value = -int(term[4:], 16)
            except Exception:
                value = None
        elif term.startswith("arg_"):
            try:
                value = int(term[4:], 16)
            except Exception:
                value = None
        elif term.startswith("0x"):
            try:
                value = int(term, 16)
            except Exception:
                value = None
        elif term.endswith("h"):
            try:
                value = int(term[:-1], 16)
            except Exception:
                value = None
        elif term.isdigit():
            try:
                value = int(term, 10)
            except Exception:
                value = None

        if value is None:
            return None

        total += sign * value

    return total


def _normalize_stack_slot(token: str) -> Optional[str]:
    """Normalize [rsp+..]/[rbp-..] style operands so stores/loads can match."""
    if not token:
        return None

    text = token.lower().replace(" ", "")
    match = re.search(r"\[((?:r|e)(?:sp|bp))(.*?)\]", text)
    if not match:
        return None

    base = match.group(1)
    expr = match.group(2) or ""

    offset = _parse_stack_offset_expr(expr)
    if offset is None:
        return None

    return f"{base}{offset:+#x}"


def _stack_slot_add(slot: str, delta: int) -> Optional[str]:
    """Add byte offset to normalized stack slot key (e.g., rbp-0xc0 + 0x90)."""
    match = re.match(r"^(r(?:bp|sp))([+-]0x[0-9a-f]+)$", slot)
    if not match:
        return None

    base = match.group(1)
    try:
        offset = int(match.group(2), 16)
    except Exception:
        return None

    return f"{base}{offset + delta:+#x}"


def _extract_assigned_address(db: ida_domain.Database, insn) -> Optional[int]:
    """Extract an address-like source operand value from mov/lea instruction."""
    try:
        operands = db.instructions.get_operands(insn)
    except Exception:
        return None
    if not operands:
        return None

    # For mov/lea, operand #0 is destination register, so prioritize sources.
    candidate_ops = operands[1:] if len(operands) > 1 else operands

    for op in candidate_ops:
        addr = None
        try:
            if isinstance(op, MemoryOperand):
                addr = op.get_address()
            elif isinstance(op, ImmediateOperand):
                addr = op.get_value()
        except Exception:
            addr = None

        if addr and db.is_valid_ea(addr):
            return addr

    # Fallback for unusual operand ordering.
    for op in operands:
        addr = None
        try:
            if isinstance(op, MemoryOperand):
                addr = op.get_address()
            elif isinstance(op, ImmediateOperand):
                addr = op.get_value()
        except Exception:
            addr = None

        if addr and db.is_valid_ea(addr):
            return addr

    return None


def _simulate_argument_state(
    db: ida_domain.Database, func, call_ea: int, search_limit: int = 120
) -> Tuple[
    Dict[str, List[int]],
    Dict[str, Optional[int]],
    Dict[str, Optional[int]],
    Dict[str, str],
]:
    """Simulate local arg-setup dataflow before a call.

    Returns:
        (register_candidates, register_values, stack_values, register_stack_bases)
    """
    candidates: Dict[str, List[int]] = {reg: [] for reg in REGISTER_ALIASES.keys()}
    reg_values: Dict[str, Optional[int]] = {}
    stack_values: Dict[str, Optional[int]] = {}
    reg_stack_bases: Dict[str, str] = {}

    prev_insn = db.instructions.get_previous(call_ea)
    if not prev_insn:
        return candidates, reg_values, stack_values, reg_stack_bases

    # Build a local instruction window and simulate forwards to handle
    # register-to-register and stack spill/reload patterns.
    window = []
    current_ea = prev_insn.ea
    while len(window) < search_limit and current_ea >= func.start_ea:
        insn = db.instructions.get_at(current_ea)
        if not insn:
            break
        window.append(insn)

        prev = db.instructions.get_previous(current_ea)
        if not prev or prev.ea >= current_ea:
            break
        current_ea = prev.ea

    window.reverse()

    for insn in window:
        disasm_text = db.instructions.get_disassembly(insn)
        if not disasm_text:
            continue

        disasm = disasm_text.lower()

        # Parse basic move-like instruction forms.
        match = re.match(r"^\s*(lea|mov|movabs)\s+(.+?),\s*(.+)\s*$", disasm)
        if not match:
            continue

        opcode = match.group(1)
        dst_text = match.group(2)
        src_text = match.group(3)

        dst_reg = _normalize_register_token(dst_text)
        src_reg = _normalize_register_token(src_text)
        dst_stack = _normalize_stack_slot(dst_text)
        src_stack = _normalize_stack_slot(src_text)

        resolved_value = _extract_assigned_address(db, insn)
        if resolved_value is None and src_reg is not None:
            resolved_value = reg_values.get(src_reg)
        if resolved_value is None and src_stack is not None:
            resolved_value = stack_values.get(src_stack)

        # Destination register write.
        if dst_reg is not None:
            reg_values[dst_reg] = resolved_value

            if opcode == "lea" and src_stack is not None:
                reg_stack_bases[dst_reg] = src_stack
            elif src_reg is not None and src_reg in reg_stack_bases:
                reg_stack_bases[dst_reg] = reg_stack_bases[src_reg]
            elif dst_reg in reg_stack_bases:
                del reg_stack_bases[dst_reg]

            if dst_reg in REGISTER_ALIASES and resolved_value is not None:
                if db.is_valid_ea(resolved_value):
                    candidates[dst_reg].append(resolved_value)
            continue

        # Destination stack slot write.
        if dst_stack is not None:
            stack_values[dst_stack] = resolved_value

    return candidates, reg_values, stack_values, reg_stack_bases


def _extract_descriptor_arguments(
    db: ida_domain.Database,
    reg_values: Dict[str, Optional[int]],
    stack_values: Dict[str, Optional[int]],
    reg_stack_bases: Dict[str, str],
) -> Optional[Tuple[int, str, str]]:
    """Try extracting (global_ptr, name) from descriptor-style call setup.

    Returns:
        (global_var_ea, name, descriptor_pattern_name)
    """
    for pattern in DESCRIPTOR_PATTERNS:
        arg_reg = pattern["arg_reg"]
        name_off = pattern["name_off"]
        global_off = pattern["global_off"]

        # Case 1: descriptor lives on stack and arg register holds &stack_slot.
        base_slot = reg_stack_bases.get(arg_reg)
        if base_slot:
            name_slot = _stack_slot_add(base_slot, name_off)
            global_slot = _stack_slot_add(base_slot, global_off)
            if name_slot and global_slot:
                name_ptr = stack_values.get(name_slot)
                global_ptr = stack_values.get(global_slot)
                if name_ptr and global_ptr and db.is_valid_ea(global_ptr):
                    name = _read_console_name(db, name_ptr)
                    if name:
                        return global_ptr, name, pattern["name"]

        # Case 2: descriptor is a static/global struct and arg register holds EA.
        desc_ptr = reg_values.get(arg_reg)
        if desc_ptr and db.is_valid_ea(desc_ptr):
            try:
                name_ptr = db.bytes.get_qword_at(desc_ptr + name_off)
                global_ptr = db.bytes.get_qword_at(desc_ptr + global_off)
            except Exception:
                continue
            if name_ptr and global_ptr and db.is_valid_ea(global_ptr):
                name = _read_console_name(db, name_ptr)
                if name:
                    return global_ptr, name, pattern["name"]

    return None


def _read_console_name(db: ida_domain.Database, name_str_ea: int) -> Optional[str]:
    """Read and validate a ConVar/ConCommand name string from memory."""
    try:
        name = db.bytes.get_cstring_at(name_str_ea)
    except Exception:
        return None

    if not name:
        return None

    # Keep this strict enough to filter unrelated strings but broad enough for commands.
    if not name.isascii():
        return None
    if not CONSOLE_NAME_RE.match(name):
        return None
    if all(c in "_" for c in name):
        return None

    return name


def _is_call_or_jump(disasm: str) -> bool:
    """Return True if a disassembly line is a direct call/jump instruction."""
    if not disasm:
        return False
    text = disasm.lstrip().lower()
    return text.startswith("call") or text.startswith("jmp")


def _collect_callsites_with_wrapper_expansion(
    db: ida_domain.Database,
    target_ea: int,
    max_depth: int = 3,
    max_callsites: int = 5000,
) -> List[int]:
    """Collect callsites to target, then recursively to wrapper callers.

    On Linux binaries, registration often flows through thin wrappers, so direct
    xrefs to the register function may not contain argument setup. This function
    walks up the call graph a few levels and returns all reachable callsites.
    """
    callsites: List[int] = []
    seen_callsites: Set[int] = set()
    seen_callees: Set[int] = set()
    queue: Deque[Tuple[int, int]] = deque([(target_ea, 0)])

    while queue:
        callee_ea, depth = queue.popleft()
        if callee_ea in seen_callees:
            continue
        seen_callees.add(callee_ea)

        for xref in db.xrefs.to_ea(callee_ea):
            call_ea = xref.from_ea
            insn = db.instructions.get_at(call_ea)
            if not insn:
                continue

            disasm = db.instructions.get_disassembly(insn)
            if not disasm or not _is_call_or_jump(disasm):
                continue

            if call_ea not in seen_callsites:
                seen_callsites.add(call_ea)
                callsites.append(call_ea)
                if len(callsites) >= max_callsites:
                    return callsites

            if depth >= max_depth:
                continue

            caller_func = db.functions.get_at(call_ea)
            if not caller_func:
                continue

            if caller_func.start_ea not in seen_callees:
                queue.append((caller_func.start_ea, depth + 1))

    return callsites


def extract_call_arguments(
    db: ida_domain.Database, call_ea: int, debug: bool = True
) -> Optional[Tuple[int, str]]:
    """
    Extract the global variable address and name string from a register call.

    Both ConVar (CConVarRef::Register) and ConCommand pass:
        - arg1: Pointer to global variable
        - arg2: Name string pointer

    Register mapping depends on ABI:
        - Windows x64: RCX / RDX
        - Linux SysV x64: RDI / RSI (or RSI / RDX for member-call style)

    Args:
        db: IDA database instance
        call_ea: Address of the call instruction

    Returns:
        Tuple of (global_var_ea, name_string) or None if extraction fails
    """
    func = db.functions.get_at(call_ea)
    if not func:
        return None

    candidates, reg_values, stack_values, reg_stack_bases = _simulate_argument_state(
        db, func, call_ea
    )

    # Try known ABI pairs first.
    for global_reg, name_reg, abi_name in ARG_REGISTER_PAIRS:
        global_candidates = candidates.get(global_reg, [])
        name_candidates = candidates.get(name_reg, [])

        if not global_candidates or not name_candidates:
            continue

        global_var_ea = global_candidates[-1]
        name_str_ea = name_candidates[-1]
        name = _read_console_name(db, name_str_ea)
        if name:
            if debug:
                print(
                    "[ConVarRenamer]     DEBUG: "
                    f"Using {abi_name} pair {global_reg}/{name_reg} -> "
                    f"global={hex(global_var_ea)}, name_ptr={hex(name_str_ea)}"
                )
            return (global_var_ea, name)

    # Fallback: mix-and-match from likely global/name registers.
    global_pool = (
        candidates.get("rcx", [])
        + candidates.get("rdi", [])
        + candidates.get("rsi", [])
    )
    name_pool = candidates.get("rdx", []) + candidates.get("rsi", [])

    for global_var_ea in reversed(global_pool):
        for name_str_ea in reversed(name_pool):
            if global_var_ea == name_str_ea:
                continue
            name = _read_console_name(db, name_str_ea)
            if name:
                if debug:
                    print(
                        "[ConVarRenamer]     DEBUG: "
                        f"Using fallback registers -> global={hex(global_var_ea)}, "
                        f"name_ptr={hex(name_str_ea)}"
                    )
                return (global_var_ea, name)

    descriptor_result = _extract_descriptor_arguments(
        db, reg_values, stack_values, reg_stack_bases
    )
    if descriptor_result:
        global_var_ea, name, pattern_name = descriptor_result
        if debug:
            print(
                "[ConVarRenamer]     DEBUG: "
                f"Using descriptor pattern {pattern_name} -> "
                f"global={hex(global_var_ea)}, name={name}"
            )
        return (global_var_ea, name)

    if debug:
        print(
            "[ConVarRenamer]     DEBUG: No usable arg register pair found "
            f"for call at {hex(call_ea)} "
            f"(rcx={len(candidates['rcx'])}, rdx={len(candidates['rdx'])}, "
            f"rdi={len(candidates['rdi'])}, rsi={len(candidates['rsi'])})"
        )

    return None


def _collect_registration_kind(
    db: ida_domain.Database,
    register_ea: Optional[int],
    kind_label_singular: str,
    kind_label: str,
    summary_label_plural: str,
    result_tag: str,
    seen_addresses: Set[int],
    verbose: bool,
) -> List[Tuple[int, str, str]]:
    """Collect and parse callsites for one registration kind."""
    if not register_ea:
        return []

    _log(verbose, f"[ConVarRenamer] Processing {kind_label} registrations...")
    callsites = _collect_callsites_with_wrapper_expansion(db, register_ea)
    _log(
        verbose,
        f"[ConVarRenamer]   Expanded to {len(callsites)} callsite(s) "
        f"from register function {hex(register_ea)}",
    )

    found: List[Tuple[int, str, str]] = []
    for call_ea in callsites:
        result = extract_call_arguments(db, call_ea, debug=verbose)
        if result is None:
            _log(
                verbose,
                f"[ConVarRenamer]   WARNING: Failed to extract arguments from call at {hex(call_ea)}",
            )
            continue

        global_var_ea, name = result
        if global_var_ea in seen_addresses:
            continue

        seen_addresses.add(global_var_ea)
        found.append((global_var_ea, name, result_tag))
        _log(
            verbose,
            f"[ConVarRenamer]   Found {kind_label_singular}: {name} at {hex(global_var_ea)}",
        )

    _log(
        verbose,
        f"[ConVarRenamer] Processed {len(callsites)} {kind_label} callsites, "
        f"found {len(found)} unique {summary_label_plural}",
    )
    return found


def collect_convars_and_concommands(
    db: ida_domain.Database,
    convar_register_ea: Optional[int],
    concommand_register_ea: Optional[int],
    verbose: bool = True,
) -> List[Tuple[int, str, str]]:
    """
    Collect all ConVar and ConCommand global variables with their names.

    Returns:
        List of tuples: (global_var_ea, name, type)
        where type is "convar" or "concommand"
    """
    seen_addresses: Set[int] = set()
    results = _collect_registration_kind(
        db,
        convar_register_ea,
        kind_label_singular="ConVar",
        kind_label="ConVar",
        summary_label_plural="ConVars",
        result_tag="convar",
        seen_addresses=seen_addresses,
        verbose=verbose,
    )

    results.extend(
        _collect_registration_kind(
            db,
            concommand_register_ea,
            kind_label_singular="ConCommand",
            kind_label="ConCommand",
            summary_label_plural="ConCommands",
            result_tag="concommand",
            seen_addresses=seen_addresses,
            verbose=verbose,
        )
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


def _try_alternate_candidate_pairs(
    db: ida_domain.Database,
    primary_pair: Tuple[Optional[int], Optional[int]],
    convar_candidates: List[int],
    concommand_candidates: List[int],
) -> Tuple[Tuple[Optional[int], Optional[int]], List[Tuple[int, str, str]]]:
    """Try alternate candidate pairs and return the best scoring result."""
    print(
        "[ConVarRenamer] Primary candidate pair produced no results, "
        "trying alternate register-function candidates..."
    )

    primary_convar, primary_concommand = primary_pair
    convar_try = convar_candidates if convar_candidates else [None]
    concommand_try = concommand_candidates if concommand_candidates else [None]

    best_pair = primary_pair
    best_renames: List[Tuple[int, str, str]] = []

    for cv_ea in convar_try:
        for cc_ea in concommand_try:
            if cv_ea == primary_convar and cc_ea == primary_concommand:
                continue

            try:
                trial = collect_convars_and_concommands(db, cv_ea, cc_ea, verbose=False)
            except Exception as e:
                print(
                    "[ConVarRenamer]   Trial "
                    f"ConVar={hex(cv_ea) if cv_ea else 'None'}, "
                    f"ConCommand={hex(cc_ea) if cc_ea else 'None'} failed: {e}"
                )
                continue

            print(
                "[ConVarRenamer]   Trial "
                f"ConVar={hex(cv_ea) if cv_ea else 'None'}, "
                f"ConCommand={hex(cc_ea) if cc_ea else 'None'} -> "
                f"{len(trial)} item(s)"
            )

            if len(trial) > len(best_renames):
                best_renames = trial
                best_pair = (cv_ea, cc_ea)

    return best_pair, best_renames


def run_convar_renamer(db: ida_domain.Database) -> None:
    """
    Main entry point for the ConVar/ConCommand renamer tool.
    """
    print("[ConVarRenamer] Starting ConVar/ConCommand renamer...")

    # Step 1: Find the registration functions
    (
        convar_register_ea,
        concommand_register_ea,
        convar_candidates,
        concommand_candidates,
    ) = find_register_functions(db)

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

    # If primary candidates fail, try alternative candidates discovered from
    # the same error strings (common on Linux where flush/control helpers have
    # more xrefs than the actual descriptor registrar).
    if not renames and (len(convar_candidates) > 1 or len(concommand_candidates) > 1):
        best_pair, best_renames = _try_alternate_candidate_pairs(
            db,
            (convar_register_ea, concommand_register_ea),
            convar_candidates,
            concommand_candidates,
        )
        if best_renames:
            convar_register_ea, concommand_register_ea = best_pair
            renames = best_renames
            print(
                "[ConVarRenamer] Using alternate candidate pair: "
                f"ConVar={hex(convar_register_ea) if convar_register_ea else 'None'}, "
                f"ConCommand={hex(concommand_register_ea) if concommand_register_ea else 'None'}"
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
