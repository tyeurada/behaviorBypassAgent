"""Approach tracking and compact iteration summaries for the agent loop.

These helpers parse the analysis agent's plan text and maintain the
approach_tracker / banned_approaches / iteration_summaries state fields.
"""

import re


def _extract_approach_name(ai_plan: str, iteration: int) -> str:
    """Extract approach name from AI plan or return baseline/unknown."""
    if iteration == 0:
        return "baseline_rwx"

    if not ai_plan:
        return "unknown_approach"

    ai_plan_lower = ai_plan.lower()

    # Known techniques from config/convention
    known_techniques = [
        "safe_memory_transition",
        "rw_to_rx",
        "module_stomping",
        "module_remapping",
        "heap_execution",
        "heap_based",
        "fiber_execution",
        "fiber_usage",
        "fiber_context",
        "native_api_direct",
        "direct_syscalls",
        "callback_usage",
        "indirect_execution",
        "rop_chain",
        "thread_hijacking",
    ]

    # 1. Primary Method: Explicit 'Technique' field
    match = re.search(r"\*\*Technique\*\*:\s*([^\n]+)", ai_plan, re.IGNORECASE)
    if match:
        extracted = match.group(1).strip().lower()
        # Clean up Markdown bolding if present
        extracted = extracted.replace("**", "").replace("*", "").strip()
        # Return if it matches a known one, or just return the string (truncated)
        known_match = next((t for t in known_techniques if t in extracted), None)
        if known_match:
            return known_match
        return extracted[:50]  # Return custom name if valid

    # 2. Fallback: Keyword Matching
    for tech in known_techniques:
        if tech in ai_plan_lower:
            return tech

    # 3. Fallback: Methodology extraction
    match = re.search(r"\*\*Methodology\*\*:\s*(.+)", ai_plan, re.IGNORECASE)
    if match:
        return match.group(1).strip()[:50]

    return "unknown_approach"


def _build_compact_summary(ai_plan: str, outcome: str, rules: list[str]) -> str:
    """Build a short summary string for prompt injection."""
    if not ai_plan:
        analysis_snippet = "No analysis provided"
        assessment = "Assessment: Unknown"
    else:
        # Extract Analysis
        match = re.search(r"\*\*Analysis\*\*:\s*(.+?)(?:\.|$)", ai_plan, re.DOTALL)
        if match:
            analysis_snippet = match.group(1).strip()[:80]
        else:
            analysis_snippet = ai_plan[:80].replace("\n", " ")

        # Extract Rule Assessment (Loophole/No Loophole)
        match_assess = re.search(r"\*\*Rule_Analysis\*\*:\s*([^\n]+)", ai_plan, re.IGNORECASE)
        if match_assess:
            assessment = match_assess.group(1).strip()
        else:
            assessment = "Assessment: Unknown"

    rules_str = ", ".join(rules) if rules else "None"
    summary = f"[{outcome}] Rules: {rules_str} | {assessment} | Analysis: {analysis_snippet}."
    return summary[:250]  # Increased cap slightly


def _update_approach_tracker(
    tracker: list[dict],
    banned: list[str],
    approach_name: str,
    iteration: int,
    outcome: str,
    rules: list[str],
    summary: str,
) -> tuple:
    """Update the approach tracker state."""

    # Find existing approach entry
    entry = next((item for item in tracker if item["approach_name"] == approach_name), None)

    if not entry:
        entry = {
            "approach_name": approach_name,
            "attempts": 0,
            "status": "active",
            "rule_target": rules[0] if rules else "unknown",
            "iteration_results": [],
        }
        tracker.append(entry)

    # Update entry
    entry["attempts"] += 1
    entry["iteration_results"].append(
        {"iteration": iteration, "outcome": outcome, "rules_triggered": rules, "summary": summary}
    )

    # Check for success
    if outcome == "clean":
        entry["status"] = "succeeded"

    # Check for exhaustion (3 attempts total per approach)
    if entry["attempts"] >= 3 and outcome != "clean":
        entry["status"] = "exhausted"
        if approach_name not in banned:
            banned.append(approach_name)

    return tracker, banned
