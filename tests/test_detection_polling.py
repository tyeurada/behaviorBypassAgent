from core import nodes


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeDetection:
    def to_dict(self):
        return {"detected": True, "rule_name": "test rule"}


class FakeDetector:
    def __init__(self, detect_on_call=None):
        self.calls = 0
        self.detect_on_call = detect_on_call

    def is_available(self):
        return True

    def check_detection(self, **kwargs):
        self.calls += 1
        if self.calls == self.detect_on_call:
            return [FakeDetection()]
        return []


def run_detection_check(monkeypatch, elastic_config, detector, *, status="executed", shellcode_success=True):
    clock = FakeClock()
    config = {"detectors": {"elastic": elastic_config}}
    monkeypatch.setattr(nodes.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(nodes.time, "sleep", clock.sleep)
    monkeypatch.setattr(
        nodes,
        "_get_components",
        lambda: (config, None, None, [detector], None, None),
    )
    update = nodes.check_detections({
        "compile_result": {"output_path": "loader.exe"},
        "exec_result": {"shellcode_success": shellcode_success},
        "status": status,
    })
    return update, clock


def test_poll_schedule_uses_absolute_offsets_without_final_sleep(monkeypatch):
    detector = FakeDetector()
    update, clock = run_detection_check(
        monkeypatch,
        {"poll_schedule_seconds": [0, 5, 15, 30]},
        detector,
    )

    assert detector.calls == 4
    assert clock.sleeps == [5.0, 10.0, 15.0]
    assert update["status"] == "clean"


def test_poll_schedule_stops_as_soon_as_detection_is_found(monkeypatch):
    detector = FakeDetector(detect_on_call=3)
    update, clock = run_detection_check(
        monkeypatch,
        {"poll_schedule_seconds": [0, 5, 15, 30, 60]},
        detector,
    )

    assert detector.calls == 3
    assert clock.sleeps == [5.0, 10.0]
    assert update["status"] == "detected"


def test_legacy_polling_has_no_sleep_after_last_check(monkeypatch):
    detector = FakeDetector()
    _, clock = run_detection_check(
        monkeypatch,
        {"max_checks": 3, "check_interval": 5},
        detector,
    )

    assert clock.sleeps == [5.0, 5.0]


def test_detection_overrides_crashed_exec_failed(monkeypatch):
    detector = FakeDetector(detect_on_call=2)
    update, clock = run_detection_check(
        monkeypatch,
        {"poll_schedule_seconds": [0, 5, 15]},
        detector,
        status="exec_failed",
        shellcode_success=False,
    )

    assert detector.calls == 2
    assert clock.sleeps == [5.0]
    assert update["status"] == "detected"
    assert update["detections"][0]["rule_name"] == "test rule"
