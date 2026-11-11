"""Prompt template loader.

Prompts live in ``prompts/*.j2`` (Jinja2 templates) so that prompt text is
versioned and diffable independently of the Python code that fills them.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(str(_PROMPTS_DIR)),
    keep_trailing_newline=True,
    autoescape=False,
)


def render_prompt(template_name: str, **context) -> str:
    """Render a prompt template by name (without the .j2 extension)."""
    return _env.get_template(f"{template_name}.j2").render(**context)
