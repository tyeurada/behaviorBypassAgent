"""Prompt template rendering tests — every template must render and keep
the output-format markers the response parser relies on."""

import pytest

from lib.code_templates import language_context
from lib.prompt_builder import render_prompt


@pytest.mark.parametrize("lang", ["c", "csharp", "python"])
def test_generate_iter1_renders(lang):
    lc = language_context(lang)
    out = render_prompt(
        "generate_iter1",
        lang_name=lc["lang_name"],
        shellcode_path="C:/x/payload.bin",
        shellcode_size=512,
        args_name=lc["args_name"],
        code_block_tag=lc["code_block_tag"],
        file_tpl=lc["file_tpl"],
        validation_patterns_block="- mod",
        preferred_instruction_block="",
        techniques_kb_block="",
        comment_prefix=lc["comment_prefix"],
    )
    assert "payload.bin" in out
    assert "### CODE" in out


@pytest.mark.parametrize("lang", ["c", "csharp", "python"])
def test_generate_iterN_renders(lang):
    lc = language_context(lang)
    out = render_prompt(
        "generate_iterN",
        iteration=3,
        lang_name=lc["lang_name"],
        previous_code="// prev",
        code_block_tag=lc["code_block_tag"],
        diagnostic_info="DIAG",
        ai_plan="PLAN",
        validation_patterns_block="- mod",
        preferred_instruction_block="",
        techniques_kb_block="KB BODY",
        comment_prefix=lc["comment_prefix"],
    )
    assert "DIAG" in out and "PLAN" in out and "KB BODY" in out
    assert "### CODE" in out


def test_analysis_detected_renders_detection_block():
    out = render_prompt(
        "analysis_detected",
        history_block="HB",
        rule_analysis_block="RB",
        status_block="SB",
        banned_block="banned_x",
        generic_malware_alert=False,
        context="CTX",
        detection_info="DET-INFO",
        standard_techniques_block="TB",
        lang_specific_rules_block="LB",
        techniques_kb_block="KB",
    )
    for marker in ("HB", "RB", "SB", "banned_x", "CTX", "DET-INFO", "TB", "LB", "KB"):
        assert marker in out


def test_analysis_detected_generic_malware_flag():
    base = dict(
        history_block="",
        rule_analysis_block="",
        status_block="",
        banned_block="",
        context="",
        detection_info="",
        standard_techniques_block="",
        lang_specific_rules_block="",
        techniques_kb_block="",
    )
    on = render_prompt("analysis_detected", generic_malware_alert=True, **base)
    off = render_prompt("analysis_detected", generic_malware_alert=False, **base)
    assert "GENERIC MALWARE ALERT" in on
    assert "GENERIC MALWARE ALERT" not in off


@pytest.mark.parametrize("tpl", ["analysis_compile_failed", "analysis_exec_failed"])
def test_analysis_failure_templates(tpl):
    lc = language_context("c")
    out = render_prompt(
        tpl,
        standard_techniques_block="TB",
        lang_name=lc["analysis_lang_name"],
        code_block_tag=lc["code_block_tag"],
        code_that_failed="bad code",
        detection_info="ERR",
        techniques_kb_block="",
    )
    assert "ERR" in out and "bad code" in out


def test_review_templates_render():
    lc = language_context("c")
    sys_p = render_prompt("review_system", lang_name=lc["review_lang_name"], compiler_name=lc["compiler_name"])
    usr = render_prompt(
        "review_user",
        ai_plan="PLAN",
        iteration=1,
        current_code="int main(){}",
        code_block_tag="c",
        comment_prefix="//",
        lang_name="C code",
    )
    assert "REVIEW_ANALYSIS" in sys_p or "REVIEW_ANALYSIS" in usr
    assert "int main" in usr


def test_retry_templates_render():
    s = render_prompt("retry_refusal_system", lang_name="C", code_block_tag="c", args_name="argv[1]")
    u = render_prompt("retry_refusal_user", base_prompt="BP", lang_name="C", code_block_tag="c")
    assert "BP" in u and len(s) > 0
    for tpl in ("retry_fallback_system", "retry_fallback_user"):
        out = render_prompt(tpl, is_python=False, is_csharp=False)
        assert len(out) > 0
