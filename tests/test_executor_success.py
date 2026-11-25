from core import nodes
from lib.executor import ExecutionResult, Executor


def process_executor():
    return Executor({
        "wait_after_execute": 0,
        "success_criteria": {
            "enabled": True,
            "type": "process",
            "process": {"name": "CalculatorApp.exe", "timeout": 0.01},
        },
    })


def test_process_success_rejects_preexisting_or_too_early_processes(monkeypatch):
    executor = process_executor()
    monkeypatch.setattr(
        executor,
        "_list_matching_processes",
        lambda _: {10: 100.0, 11: 199.0},
    )

    match = executor._check_process_success_once(
        "CalculatorApp.exe",
        process_baseline={10: 100.0},
        process_started_after=200.0,
    )

    assert match is None


def test_process_success_accepts_new_identity_started_during_execution(monkeypatch):
    executor = process_executor()
    monkeypatch.setattr(
        executor,
        "_list_matching_processes",
        lambda _: {10: 201.0},
    )

    match = executor._check_process_success_once(
        "CalculatorApp.exe",
        process_baseline={10: 100.0},
        process_started_after=200.0,
    )

    assert match == {"process_id": 10, "process_start_time": 201.0}


def test_nonzero_exit_rejects_correlated_process_success(monkeypatch, tmp_path):
    executor = process_executor()
    executor.wait_after_execute = 150
    snapshots = iter([{}, {44: 9999999999.0}])
    monkeypatch.setattr(executor, "_list_matching_processes", lambda _: next(snapshots))
    sleeps = []
    monkeypatch.setattr("lib.executor.time.sleep", lambda seconds: sleeps.append(seconds))

    class FailedProcess:
        pid = 123
        returncode = 1

        def poll(self):
            return None

        def communicate(self, timeout=None):
            return b"", b"loader failed"

    monkeypatch.setattr("lib.executor.subprocess.Popen", lambda *args, **kwargs: FailedProcess())

    loader = tmp_path / "loader.exe"
    payload = tmp_path / "calc.bin"
    loader.write_bytes(b"loader")
    payload.write_bytes(b"payload")

    result = executor.execute_with_shellcode(str(loader), str(payload), timeout=1)

    assert result.success is False
    assert result.exit_code == 1
    assert result.crashed is True
    assert result.shellcode_success is False
    assert sleeps == []


def test_execute_node_prioritizes_loader_failure(monkeypatch):
    result = ExecutionResult(
        success=False,
        exit_code=1,
        error="loader failed",
        crashed=True,
        process_id=123,
        shellcode_success=True,
    )

    class FailedExecutor:
        def execute_with_shellcode(self, **kwargs):
            return result

    monkeypatch.setattr(
        nodes,
        "_get_components",
        lambda: ({}, None, FailedExecutor(), [], None, None),
    )

    update = nodes.execute_code({
        "compile_result": {"output_path": "loader.exe"},
        "shellcode_path": "calc.bin",
    })

    assert update["status"] == "exec_failed"
    assert update["exec_result"]["crashed"] is True
    assert update["exec_result"]["error"] == "loader failed"


def test_detection_check_cannot_turn_exec_failed_into_clean(monkeypatch):
    config = {"detectors": {"elastic": {"max_checks": 1, "check_interval": 0}}}
    monkeypatch.setattr(
        nodes,
        "_get_components",
        lambda: (config, None, None, [], None, None),
    )

    update = nodes.check_detections({
        "compile_result": {"output_path": "loader.exe"},
        "exec_result": {"shellcode_success": True},
        "status": "exec_failed",
    })

    assert update["status"] == "exec_failed"
