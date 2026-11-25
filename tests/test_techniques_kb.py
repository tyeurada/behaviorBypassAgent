from lib.techniques_kb import format_techniques_kb


def test_format_techniques_kb_excludes_disabled_and_stale_preferred(tmp_path):
    (tmp_path / "enabled.md").write_text("enabled notes", encoding="utf-8")
    (tmp_path / "disabled.md").write_text("disabled notes", encoding="utf-8")

    out = format_techniques_kb(
        {},
        enabled_names=["enabled"],
        preferred_names=["disabled"],
        knowledge_dir=tmp_path,
    )

    assert "enabled notes" in out
    assert "disabled" not in out.lower()


def test_format_techniques_kb_is_empty_when_all_techniques_disabled(tmp_path):
    (tmp_path / "disabled.md").write_text("disabled notes", encoding="utf-8")

    out = format_techniques_kb(
        {},
        enabled_names=[],
        preferred_names=[],
        knowledge_dir=tmp_path,
    )

    assert out == ""
