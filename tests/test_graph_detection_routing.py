from core import graph as graph_module


def test_crashed_execution_still_routes_through_detection(monkeypatch):
    calls = []

    monkeypatch.setattr(graph_module, "initialize_state", lambda state: {})
    monkeypatch.setattr(graph_module, "generate_code", lambda state: {})
    monkeypatch.setattr(graph_module, "review_code", lambda state: {})
    monkeypatch.setattr(
        graph_module,
        "compile_code",
        lambda state: {
            "status": "compiled",
            "compile_result": {"success": True, "output_path": "loader.exe"},
        },
    )
    monkeypatch.setattr(
        graph_module,
        "execute_code",
        lambda state: {
            "status": "exec_failed",
            "exec_result": {"crashed": True, "shellcode_success": False},
        },
    )

    def detect(state):
        calls.append("detect")
        return {"status": "exec_failed", "detections": []}

    monkeypatch.setattr(graph_module, "check_detections", detect)
    monkeypatch.setattr(graph_module, "analyze_results", lambda state: {})
    monkeypatch.setattr(graph_module, "record_history", lambda state: {})
    monkeypatch.setattr(graph_module, "check_next_step", lambda state: "end")

    graph = graph_module.create_graph()
    graph.invoke(
        {
            "shellcode_path": "calc.bin",
            "max_iterations": 1,
            "iteration": 1,
            "status": "start",
            "history": [],
            "analysis_report": {},
            "detections": [],
            "bug_retries": 0,
            "max_bug_retries": 1,
            "approach_tracker": [],
            "iteration_summaries": [],
            "banned_approaches": [],
        }
    )

    assert calls == ["detect"]
