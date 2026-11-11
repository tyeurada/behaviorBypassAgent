"""Format EDR detection alerts (and their matched local TOML rules) for LLM prompts.

The prompt builders need detection context as a compact, structured markdown
block: which rule fired, its local TOML definition (query / patterns /
exclusions) when available, and the relevant alert fields. This module is the
single place that knows how to render that block.
"""

from typing import Any

MAX_ALERTS = 10
MAX_QUERY_CHARS = 2000


def _get(det: dict[str, Any], *path, default=None):
    """Safe nested dict getter."""
    cur = det
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def _format_patterns(patterns: dict[str, list[str]]) -> str:
    lines = []
    labels = {
        "api_calls": "API/Behavior indicators",
        "file_paths": "File paths",
        "process_names": "Process names",
        "memory_protections": "Memory protections",
        "behaviors": "Behavior keywords",
        "exclusions": "Exclusions/allowlists",
    }
    for key, label in labels.items():
        values = patterns.get(key) or []
        if values:
            joined = ", ".join(str(v) for v in values[:20])
            lines.append(f"    - {label}: {joined}")
    return "\n".join(lines)


def format_single_detection(index: int, det: dict[str, Any], rule_analysis: dict[str, Any] | None = None) -> str:
    """Render one detection dict (DetectionResult.to_dict()) as markdown."""
    details = det.get("details") or {}
    rule_id = details.get("rule_id")

    lines = [
        f"### Alert {index}: {det.get('rule_name') or 'Unnamed alert'}",
        f"- Detector: {det.get('detector', 'unknown')}",
        f"- Severity: {det.get('severity', 'N/A')}",
        f"- Rule ID: {rule_id or 'N/A'}",
        f"- Process: {det.get('process_name', 'N/A')} (pid={det.get('process_id', 'N/A')})",
        f"- File: {det.get('file_path', 'N/A')}",
        f"- Description: {det.get('description', 'N/A')}",
    ]

    reason = details.get("reason")
    if reason:
        lines.append(f"- Reason: {reason}")

    threat = details.get("threat")
    if threat:
        lines.append(f"- Threat framework: {threat}")

    mem = details.get("memory_protection") or details.get("memory_allocation_type")
    if mem:
        lines.append(f"- Memory indicators: {mem}")

    # Matched local behavior rule (from BehaviorRuleAnalyzer.analyze_detection)
    if rule_analysis and rule_analysis.get("rule_found"):
        lines.append("- **Matched local rule**:")
        lines.append(f"    - Name: {rule_analysis.get('rule_name')}")
        lines.append(f"    - File: {rule_analysis.get('rule_file')}")
        lines.append(f"    - Rule ID: {rule_analysis.get('rule_id')}")
        query = (rule_analysis.get("detection_query") or "").strip()
        if len(query) > MAX_QUERY_CHARS:
            query = query[:MAX_QUERY_CHARS] + "\n... (truncated)"
        lines.append("    - Detection query:")
        for qline in query.splitlines():
            lines.append(f"        {qline}")
        patterns_block = _format_patterns(rule_analysis.get("detection_patterns") or {})
        if patterns_block:
            lines.append("    - Parsed detection patterns:")
            lines.append(patterns_block)
    elif rule_analysis is not None:
        lines.append(f"- **Matched local rule**: not found ({rule_analysis.get('message', 'no match')})")

    return "\n".join(lines)


def format_detections_for_prompt(
    detections: list[dict[str, Any]],
    rule_analyzer=None,
    max_alerts: int = MAX_ALERTS,
) -> str:
    """Render the full detection context block for prompts.

    Args:
        detections: List of detection dicts (DetectionResult.to_dict()).
        rule_analyzer: Optional BehaviorRuleAnalyzer used to match each alert
            to its local TOML rule definition.
        max_alerts: Cap on number of alerts rendered.

    Returns:
        Markdown string. Empty string when there are no detections.
    """
    if not detections:
        return ""

    lines = []
    shown = detections[:max_alerts]
    for i, det in enumerate(shown, start=1):
        rule_analysis = rule_analyzer.analyze_detection(det) if rule_analyzer else None
        lines.append(format_single_detection(i, det, rule_analysis))

    if len(detections) > max_alerts:
        lines.append(f"\n... and {len(detections) - max_alerts} more alert(s) not shown.")

    return "\n\n".join(lines)
