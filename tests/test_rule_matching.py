"""Behavior rule loading / alert-to-TOML matching tests."""

import textwrap

import pytest

from lib.detection_formatter import format_detections_for_prompt
from lib.rule_analyzer import BehaviorRuleAnalyzer

TOML_SAMPLE = textwrap.dedent(
    """
    [rule]
    id = "11111111-2222-3333-4444-555555555555"
    name = "Shellcode Injection via VirtualProtect"
    description = "Detects RW->RX transition followed by execution"
    query = '''
    process where event.action == "VirtualProtect" and
      process.Ext.api.parameters.protection == "PAGE_EXECUTE_READ" and
      not process.executable : "C:\\\\Windows\\\\explorer.exe"
    '''
    version = "1.0"
    os_list = ["windows"]
    """
)


@pytest.fixture
def analyzer(tmp_path):
    (tmp_path / "test_rule.toml").write_text(TOML_SAMPLE)
    return BehaviorRuleAnalyzer(str(tmp_path))


def _det(rule_id=None, rule_name=None):
    details = {}
    if rule_id:
        details["rule_id"] = rule_id
    return {
        "detector": "elastic",
        "rule_name": rule_name,
        "severity": "high",
        "process_name": "loader_1.exe",
        "details": details,
    }


def test_load_and_index(analyzer):
    assert len(analyzer.rules) == 1
    assert "11111111-2222-3333-4444-555555555555" in analyzer.rules_by_id
    assert "shellcode injection via virtualprotect" in analyzer.rules_by_name


def test_match_by_rule_id(analyzer):
    det = _det(rule_id="11111111-2222-3333-4444-555555555555", rule_name="different name")
    result = analyzer.analyze_detection(det)
    assert result["rule_found"] is True
    assert result["rule_name"] == "Shellcode Injection via VirtualProtect"
    assert "VirtualProtect" in result["detection_query"]


def test_match_by_name_fallback(analyzer):
    det = _det(rule_name="Shellcode Injection via VirtualProtect")
    result = analyzer.analyze_detection(det)
    assert result["rule_found"] is True


def test_no_match_returns_not_found(analyzer):
    det = _det(rule_name="Completely Unrelated Alert XYZ")
    result = analyzer.analyze_detection(det)
    assert result["rule_found"] is False


def test_formatter_includes_rule_context(analyzer):
    det = _det(rule_id="11111111-2222-3333-4444-555555555555", rule_name="X")
    block = format_detections_for_prompt([det], analyzer)
    assert "11111111-2222-3333-4444-555555555555" in block
    assert "Matched local rule" in block
    assert "VirtualProtect" in block


def test_formatter_empty_detections(analyzer):
    assert format_detections_for_prompt([], analyzer) == ""
