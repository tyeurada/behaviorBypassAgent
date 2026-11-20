"""Shared helpers for LLM invocation result handling.

Centralizes response normalization, code-block extraction, refusal detection,
and prompt-escaping helpers used by core/nodes.py (and any future agent node).
"""

import ast
import re
from typing import Any


def normalize_model_content(raw_content: Any) -> str:
    """Normalize LangChain provider response content to plain text."""
    if isinstance(raw_content, str):
        return raw_content
    if isinstance(raw_content, dict):
        if isinstance(raw_content.get("text"), str):
            return raw_content["text"]
        return str(raw_content)
    if hasattr(raw_content, "__iter__"):
        parts = []
        for part in raw_content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text_value = part.get("text")
                if isinstance(text_value, str):
                    parts.append(text_value)
                else:
                    parts.append(str(part))
            else:
                text_attr = getattr(part, "text", None)
                if isinstance(text_attr, str):
                    parts.append(text_attr)
                else:
                    parts.append(str(part))
        return "\n".join([p for p in parts if p is not None])
    return str(raw_content)


def parse_literal_dict_content(content: str) -> str:
    """If the model returned a dict repr like {'type': 'text', 'text': ...}, unwrap it."""
    try:
        if content.strip().startswith("{") and "type" in content:
            parsed = ast.literal_eval(content)
            if isinstance(parsed, dict) and 'text' in parsed:
                return parsed['text']
    except Exception:
        pass
    return content


def escape_braces(text: str) -> str:
    """Escape braces so the text is safe to embed inside an f-string template."""
    return (text or "").replace('{', '{{').replace('}', '}}')


REFUSAL_PHRASES = (
    "I cannot fulfill",
    "I cannot generate",
    "I can, however, explain",
    "I'm not able to",
    "I won't generate",
    "I can, however, provide",
    "I am not able to generate",
)


def is_refusal(content: str, head: int = 2000) -> bool:
    """Heuristic: model declined to generate a full implementation."""
    head_lower = content[:head].lower()
    return any(p.lower() in head_lower for p in REFUSAL_PHRASES)


_CODE_PATTERNS = [
    r"```c[ \t]*\r?\n(.*?)\s*```",
    r"```cpp[ \t]*\r?\n(.*?)\s*```",
    r"```csharp[ \t]*\r?\n(.*?)\s*```",
    r"```cs[ \t]*\r?\n(.*?)\s*```",
    r"```python[ \t]*\r?\n(.*?)\s*```",
    r"```py[ \t]*\r?\n(.*?)\s*```",
    r"```[ \t]*\r?\n(.*?)\s*```",
]

_PY_LANGS = ('python', 'py')
_CSHARP_LANGS = ('.net', 'csharp', 'c#')


def _looks_like_code(candidate: str, target_language: str) -> bool:
    if target_language in _PY_LANGS:
        return "sys" in candidate or "import" in candidate or "open" in candidate
    if target_language in _CSHARP_LANGS:
        return "class" in candidate or "static" in candidate or "args" in candidate or "using" in candidate
    return "#include" in candidate and "main(" in candidate


def extract_code_from_content(raw_text: str, target_language: str) -> str:
    """Extract the first plausible code block from a model response."""
    for pattern in _CODE_PATTERNS:
        match = re.search(pattern, raw_text, re.DOTALL | re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if target_language in _PY_LANGS:
                if "sys" in candidate or "import" in candidate or "open" in candidate:
                    return candidate
            elif target_language in _CSHARP_LANGS:
                if "class" in candidate or "static" in candidate or "args" in candidate or "using" in candidate:
                    return candidate
            else:
                if "#include" in candidate and "main(" in candidate:
                    return candidate
                return candidate
    text = raw_text.strip()
    if _looks_like_code(text, target_language):
        return text
    return text if len(text) > 100 else ""


_C_ENTRY_RE = re.compile(r"\b(?:int\s+)?(?:w?main|w?WinMain)\s*\(")
_C_WIDE_ENTRY_RE = re.compile(r"\b(?:wmain|wWinMain)\s*\(")
_C_NARROW_ON_ARGV_RE = re.compile(
    r"\b(?:fopen|freopen|remove|rename|strcpy|strncpy|strcat|strcmp|strlen|sscanf|atoi|puts)\s*\(\s*argv"
)
_C_NT_CALL_RE = re.compile(r"\b(?:Nt|Zw)[A-Z]\w*\s*\(")
_C_NT_TYPE_RE = re.compile(
    r"\b(?:NTSTATUS|PHANDLE|ACCESS_MASK|POBJECT_ATTRIBUTES|PIO_STATUS_BLOCK|"
    r"OBJECT_ATTRIBUTES|IO_STATUS_BLOCK|UNICODE_STRING|PUNICODE_STRING|CLIENT_ID)\b"
)
_C_WIN32_CALL_RE = re.compile(
    r"\b(?:VirtualProtect|VirtualAlloc|VirtualFree|LoadLibrary[AW]?|GetModuleHandle[AW]?|"
    r"CreateFile[AW]?|CreateThread|CreateProcess[AW]?|VirtualAllocEx|WriteProcessMemory|"
    r"ReadProcessMemory|OpenProcess|QueueUserAPC|SuspendThread|ResumeThread|GetProcAddress)\s*\("
)


def validate_c_source(code: str) -> list:
    """Structural checks for generated Windows C source before it reaches cl.exe.

    Returns a list of human-readable issues; empty means structurally plausible.
    These are cheap static heuristics — they catch truncation, missing entry
    points/includes, wide/narrow argv mismatches, and undocumented NT API usage
    without declarations (all observed failure classes). The compiler remains
    the final authority.
    """
    issues = []
    if not code or not code.strip():
        return ["empty source"]

    if not _C_ENTRY_RE.search(code):
        issues.append("no entry point (main/wmain/WinMain)")
    if "#include" not in code:
        issues.append("no #include directives")

    if code.count("{") != code.count("}"):
        issues.append("unbalanced braces (output likely truncated)")

    if _C_WIDE_ENTRY_RE.search(code) and _C_NARROW_ON_ARGV_RE.search(code):
        issues.append(
            "wmain/wWinMain passes wchar_t* argv to narrow CRT functions "
            "(e.g. fopen(argv[1])) — use _wfopen etc. or use main(int argc, char* argv[])"
        )

    uses_win32 = bool(_C_WIN32_CALL_RE.search(code))
    has_windows_h = re.search(r"#\s*include\s*<windows\.h>", code, re.IGNORECASE)
    if uses_win32 and not has_windows_h:
        issues.append("Win32 APIs used without #include <windows.h>")

    # Undocumented NT API usage: every NT type needs a real local typedef
    # (name as the alias: `typedef ... NAME;`) or <winternl.h>. A typedef that
    # merely *uses* PHANDLE in a parameter list does not declare it.
    has_winternl = "winternl.h" in code.lower()

    def _declares(name: str) -> bool:
        if has_winternl:
            return True
        pat = r"typedef[^;{}]*\b" + re.escape(name) + r"\b\s*;"
        return bool(re.search(pat, code, re.DOTALL))

    undecl_types = [t for t in {m.group(0) for m in _C_NT_TYPE_RE.finditer(code)}
                    if not _declares(t)]
    undecl_calls = []
    for m in _C_NT_CALL_RE.finditer(code):
        name = m.group(0).rstrip("(").strip()
        # accept a typedef mentioning the name (e.g. `typedef ... NtCreateFile_t`
        # does NOT count — require the bare name), a return-typed forward
        # declaration `TYPE NAME(...);`, or winternl.h coverage. A call site
        # `NtCreateFile(...);` alone must NOT satisfy the check.
        proto = re.search(
            r"typedef[^;{}]*\b" + re.escape(name) + r"\b|"
            r"(?:^|[;{}])\s*(?:[A-Za-z_]\w*\s+)+\*?\s*\b" + re.escape(name)
            + r"\s*\([^;{}]*\)\s*;",
            code, re.DOTALL | re.MULTILINE,
        )
        if not (proto or has_winternl):
            undecl_calls.append(name)

    if undecl_types or undecl_calls:
        missing = ", ".join(sorted(undecl_types + undecl_calls))
        issues.append(
            f"undocumented NT API usage without declarations ({missing}) — either "
            "include <winternl.h> or fully typedef every type/prototype "
            "(Nt*/Zw* types are NOT provided by <windows.h>)"
        )

    if issues and issues != ["empty source"]:
        tail = code.rstrip().splitlines()[-1] if code.strip() else ""
        if not tail.endswith(("}", ";", ")")):
            issues.append("file ends mid-statement (output likely truncated)")

    return issues


def code_implements_loader(code: str, target_language: str) -> bool:
    """Check the generated code reads shellcode from arguments (per strategy)."""
    if not code:
        return False
    if target_language in _PY_LANGS:
        return "sys.argv" in code or "open(" in code
    if target_language in _CSHARP_LANGS:
        return "args" in code or "File.ReadAllBytes" in code
    return "argv[1]" in code or "argv[1]" in code.replace(" ", "")


def build_safe_fallback(reason: str, target_language: str) -> str:
    """Minimal diagnostics stub used when generation is blocked/unparseable."""
    if target_language in _PY_LANGS:
        return f"""# Python safe fallback diagnostics stub
import os
import sys

print(f"[SAFE_FALLBACK] Diagnostics stub. PID={{os.getpid()}}")
print(f"[SAFE_FALLBACK] Reason: {reason}")
if len(sys.argv) > 1:
    print(f"[SAFE_FALLBACK] Input path: {{sys.argv[1]}}")
"""
    if target_language in _CSHARP_LANGS:
        return f"""// C# safe fallback diagnostics stub
using System;
using System.Diagnostics;

class Program {{
    static void Main(string[] args) {{
        int pid = Process.GetCurrentProcess().Id;
        Console.WriteLine("[SAFE_FALLBACK] Diagnostics stub. PID=" + pid);
        Console.WriteLine("[SAFE_FALLBACK] Reason: {reason}");
        if (args.Length > 0) {{
            Console.WriteLine("[SAFE_FALLBACK] Input path: " + args[0]);
        }}
    }}
}}
"""
    return f"""#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {{
    DWORD pid = GetCurrentProcessId();
    printf("[SAFE_FALLBACK] Defensive validation stub. PID=%lu\\n", (unsigned long)pid);
    printf("[SAFE_FALLBACK] Generation reason: {reason}\\n");
    if (argc > 1) {{
        printf("[SAFE_FALLBACK] Input path: %s\\n", argv[1]);
    }}
    return 0;
}}
"""
