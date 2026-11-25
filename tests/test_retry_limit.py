from core import nodes


def failed_compile_state(**updates):
    state = {
        "iteration": 1,
        "status": "compile_failed",
        "history": [],
        "current_code": "int main(void) { return 1; }",
        "ai_strategy_plan": "",
        "compile_result": {"success": False},
        "exec_result": {},
        "detections": [],
        "analysis_report": {},
        "approach_tracker": [],
        "banned_approaches": [],
        "iteration_summaries": [],
        "bug_retries": 0,
        "max_bug_retries": 2,
    }
    state.update(updates)
    return state


def test_bug_retry_limit_advances_after_configured_number_of_failures():
    state = failed_compile_state()

    first_update = nodes.record_history(state)
    assert first_update["iteration"] == 1
    assert first_update["bug_retries"] == 1

    second_update = nodes.record_history({**state, **first_update})
    assert second_update["iteration"] == 2
    assert second_update["bug_retries"] == 0
