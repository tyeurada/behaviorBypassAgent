"""Approach-tracker / iteration-summary helper tests."""

from lib.agent_memory import (
    _build_compact_summary,
    _extract_approach_name,
    _update_approach_tracker,
)


def test_extract_approach_baseline():
    assert _extract_approach_name("anything", 0) == "baseline_rwx"


def test_extract_approach_from_technique_field():
    plan = "**Technique**: module_stomping\n**Methodology**: map image section"
    assert _extract_approach_name(plan, 2) == "module_stomping"


def test_extract_approach_unknown():
    assert _extract_approach_name("", 2) == "unknown_approach"


def test_build_compact_summary():
    plan = "**Analysis**: the rule fires on RWX\n**Rule_Analysis**: no loophole found"
    s = _build_compact_summary(plan, "detected", ["rule_a"])
    assert "detected" in s and "rule_a" in s


def test_update_approach_tracker_lifecycle():
    tracker, banned = [], []
    for i in range(3):
        tracker, banned = _update_approach_tracker(tracker, banned, "heap_execution", i + 1, "detected", ["r"], "sum")
    entry = tracker[0]
    assert entry["attempts"] == 3
    assert entry["status"] == "exhausted"
    assert "heap_execution" in banned


def test_update_approach_tracker_success_not_banned():
    tracker, banned = [], []
    tracker, banned = _update_approach_tracker(tracker, banned, "fiber_execution", 1, "clean", [], "ok")
    tracker, banned = _update_approach_tracker(tracker, banned, "fiber_execution", 2, "clean", [], "ok")
    tracker, banned = _update_approach_tracker(tracker, banned, "fiber_execution", 3, "clean", [], "ok")
    assert tracker[0]["status"] == "succeeded"
    assert "fiber_execution" not in banned
