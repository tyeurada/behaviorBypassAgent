"""Tests for LLM response normalization / extraction helpers."""

from lib.llm_utils import (
    build_safe_fallback,
    code_implements_loader,
    extract_code_from_content,
    is_refusal,
    normalize_model_content,
    parse_literal_dict_content,
    validate_c_source,
)


def test_normalize_string_passthrough():
    assert normalize_model_content("abc") == "abc"


def test_normalize_anthropic_style_blocks():
    content = [{"type": "text", "text": "hello"}, {"type": "text", "text": "world"}]
    assert normalize_model_content(content) == "hello\nworld"


def test_parse_literal_dict_content():
    assert parse_literal_dict_content("{'type': 'text', 'text': 'inner'}") == "inner"
    assert parse_literal_dict_content("plain text") == "plain text"


def test_is_refusal():
    assert is_refusal("I cannot fulfill this request to generate that code.")
    assert is_refusal("I'm not able to generate that.")
    assert not is_refusal("Here is the code you requested.")


def test_extract_code_c():
    content = "### EXPLANATION\nstuff\n### CODE\n```c\n#include <windows.h>\nint main(){return 0;}\n```"
    code = extract_code_from_content(content, "c")
    assert "#include" in code and "main" in code


def test_extract_code_python():
    content = "### CODE\n```python\nimport sys\nprint(sys.argv)\n```"
    code = extract_code_from_content(content, "python")
    assert "import sys" in code


def test_extract_code_missing_returns_empty_or_fallback():
    code = extract_code_from_content("no code here", "c")
    assert isinstance(code, str)


def test_code_implements_loader():
    assert code_implements_loader("int main(int argc, char* argv[]){ open(argv[1]); }", "c")
    assert not code_implements_loader("I cannot help with malware", "c")
    assert code_implements_loader("import sys\nopen(sys.argv[1])", "python")
    assert code_implements_loader("static void Main(string[] args){ File.ReadAllBytes(args[0]); }", "csharp")


def test_build_safe_fallback_c():
    code = build_safe_fallback("SAFETY", "c")
    assert isinstance(code, str) and len(code) > 0


def test_build_safe_fallback_python():
    code = build_safe_fallback("MAX_TOKENS", "python")
    assert "import" in code or "sys" in code


def test_validate_c_source_clean():
    code = """
#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 1;
    LPVOID p = VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_READWRITE);
    VirtualProtect(p, 4096, PAGE_EXECUTE_READ, (PDWORD)&(DWORD){0});
    return 0;
}
"""
    assert validate_c_source(code) == []


def test_validate_c_source_wmain_narrow_mismatch():
    code = """#include <windows.h>
#include <stdio.h>
int wmain(int argc, wchar_t **argv) {
    FILE *fp = fopen(argv[1], "rb");
    return 0;
}
"""
    issues = validate_c_source(code)
    assert any("narrow CRT" in i for i in issues)


def test_validate_c_source_undeclared_nt_types():
    code = """#include <windows.h>
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE FileHandle, ACCESS_MASK am);
int main(){ OBJECT_ATTRIBUTES oa; NtCreateFile(h,0,&oa,0,0,0,0,0,0,0,0); return 0; }
"""
    issues = validate_c_source(code)
    assert any("PHANDLE" in i and "NtCreateFile" in i for i in issues)


def test_validate_c_source_winternl_satisfies():
    code = """#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE FileHandle);
NtCreateFile_t pNt = 0;
int main(){ pNt(h); return 0; }
"""
    assert validate_c_source(code) == []


def test_validate_c_source_truncated():
    code = "#include <windows.h>\nint main(){ LPVOID p = VirtualAlloc("
    issues = validate_c_source(code)
    assert any("truncated" in i or "unbalanced" in i for i in issues)


def test_validate_c_source_no_entry():
    code = "#include <windows.h>\nvoid helper(){ VirtualProtect(0,0,0,0); }"
    issues = validate_c_source(code)
    assert any("entry point" in i for i in issues)


def test_validate_c_source_missing_windows_h():
    code = "#include <stdio.h>\nint main(){ VirtualProtect(0,0,0,0); return 0; }"
    issues = validate_c_source(code)
    assert any("windows.h" in i for i in issues)
