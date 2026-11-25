"""Regression coverage for model responses truncated by the token limit."""

from types import SimpleNamespace

from core import nodes


def _response(content, finish_reason):
    return SimpleNamespace(
        content=content,
        response_metadata={"finish_reason": finish_reason, "safety_ratings": []},
    )


class _SequenceLlm:
    def __init__(self, responses):
        self.responses = list(responses)
        self.messages = []

    def invoke(self, messages):
        self.messages.append(messages)
        return self.responses.pop(0)


def test_length_response_gets_compact_retry_instead_of_compile_failure(
    tmp_path, monkeypatch
):
    recovered = """### CODE
```python
import sys
payload = open(sys.argv[1], "rb").read()
print(len(payload))
```
"""
    llm = _SequenceLlm(
        [
            _response("", "length"),
            _response(recovered, "stop"),
        ]
    )
    config = {
        "compiler": {"language": "python", "guidelines": {}},
        "evasion_techniques": {"memory": [], "preferred_techniques": []},
    }
    monkeypatch.setattr(
        nodes,
        "_get_components",
        lambda: (config, None, None, None, None, llm),
    )
    monkeypatch.setattr(nodes, "format_techniques_kb", lambda *args, **kwargs: "")

    shellcode = tmp_path / "payload.bin"
    shellcode.write_bytes(b"test")
    state = {
        "iteration": 2,
        "status": "detected",
        "shellcode_path": str(shellcode),
        "session_dir": str(tmp_path),
        "current_code": "# previous code",
        "ai_strategy_plan": "RULE_KEEP: retain the detection-aware plan",
        "analysis_report": {
            "detections_context": "RULE_KEEP: matched local detection query"
        },
        "detections": [],
    }

    result = nodes.generate_code(state)

    assert result["status"] == "generated"
    assert "payload = open" in result["generated_code"]
    assert len(llm.messages) == 2
    retry_text = "\n".join(message.content for message in llm.messages[1])
    assert "RULE_KEEP" in retry_text


def test_length_response_with_complete_source_is_kept_without_retry(
    tmp_path, monkeypatch
):
    complete = """### CODE
```python
import sys
payload = open(sys.argv[1], "rb").read()
print(len(payload))
```
"""
    llm = _SequenceLlm([_response(complete, "length")])
    config = {
        "compiler": {"language": "python", "guidelines": {}},
        "evasion_techniques": {"memory": [], "preferred_techniques": []},
    }
    monkeypatch.setattr(
        nodes,
        "_get_components",
        lambda: (config, None, None, None, None, llm),
    )
    monkeypatch.setattr(nodes, "format_techniques_kb", lambda *args, **kwargs: "")

    shellcode = tmp_path / "payload.bin"
    shellcode.write_bytes(b"test")
    result = nodes.generate_code(
        {
            "iteration": 2,
            "status": "detected",
            "shellcode_path": str(shellcode),
            "session_dir": str(tmp_path),
            "current_code": "# previous code",
            "ai_strategy_plan": "retain the strategy",
            "analysis_report": {"detections_context": "matched local rule"},
            "detections": [],
        }
    )

    assert result["status"] == "generated"
    assert "payload = open" in result["generated_code"]
    assert len(llm.messages) == 1

