"""Technique knowledge base loader.

Markdown notes under `evasion_techniques.knowledge_dir` (default
`./techniques/`) hold implementation guidance per technique — one file per
technique name from `evasion_techniques.memory[].name`. Enabled/preferred
techniques' notes are injected into prompts so the LLM works from curated
knowledge rather than generic priors.
"""

from pathlib import Path

DEFAULT_KB_DIR = "techniques"
MAX_FILE_CHARS = 6000


def load_kb(knowledge_dir=None, config=None) -> dict:
    """Load all technique notes as {name: markdown_text}."""
    if knowledge_dir is None and config is not None:
        knowledge_dir = (config.get("evasion_techniques", {}) or {}).get("knowledge_dir")
    base = Path(knowledge_dir or DEFAULT_KB_DIR)
    kb = {}
    if not base.is_dir():
        return kb
    for md in sorted(base.glob("*.md")):
        try:
            text = md.read_text(encoding="utf-8")
        except OSError:
            continue
        if len(text) > MAX_FILE_CHARS:
            text = text[:MAX_FILE_CHARS] + "\n\n... (truncated)"
        kb[md.stem] = text
    return kb


def format_techniques_kb(
    config: dict,
    enabled_names: list,
    preferred_names: list | None = None,
    knowledge_dir=None,
) -> str:
    """Render KB notes for enabled/preferred techniques as a markdown block.

    Only techniques with a matching `<name>.md` file are included. Preferred
    techniques are listed first.
    """
    kb = load_kb(knowledge_dir, config)
    if not kb:
        return ""

    # Config technique names (e.g. "RW_to_RX") may not match file stems
    # case-sensitively ("rw_to_rx.md"); normalize lookups by lowercase stem.
    kb_by_lower = {stem.lower(): stem for stem in kb}

    ordered = []

    def _add(names):
        for name in names or []:
            stem = kb_by_lower.get(str(name).lower())
            if stem and stem not in ordered:
                ordered.append(stem)

    if preferred_names:
        # Focused injection: preferred techniques only, to keep prompts lean.
        _add(preferred_names)
        if not ordered:
            # Preferred names have no KB notes on disk — fall back to enabled set.
            _add(enabled_names)
    else:
        _add(enabled_names)
        # Also include KB files that have no config entry (reference-only notes).
        for stem in kb:
            if stem not in ordered:
                ordered.append(stem)

    preferred_lower = {str(p).lower() for p in (preferred_names or [])}
    blocks = []
    for stem in ordered:
        tag = " [USER-PREFERRED]" if stem.lower() in preferred_lower else ""
        blocks.append(f"### {stem}{tag}\n{kb[stem].strip()}")
    return "\n\n".join(blocks)
