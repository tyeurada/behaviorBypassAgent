"""Unit tests for lib/llm_factory.py provider dispatch.

Runs with stdlib unittest (no pytest required):
    python -m unittest tests.test_llm_factory
or directly:
    python tests/test_llm_factory.py
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.llm_factory import (  # noqa: E402
    DEFAULT_OPENAI_COMPATIBLE_BASE_URL,
    OPENAI_COMPATIBLE_PLACEHOLDER_KEY,
    api_key_required,
    create_llm,
    get_provider,
    required_env_var,
)

try:
    import langchain_openai  # noqa: F401

    HAS_LANGCHAIN_OPENAI = True
except ImportError:
    HAS_LANGCHAIN_OPENAI = False


def make_config(provider_cfg=None, provider="openai_compatible"):
    return {"ai": {"provider": provider, provider: provider_cfg or {}}}


class TestProviderResolution(unittest.TestCase):
    def test_get_provider_default(self):
        self.assertEqual(get_provider({}), "gemini")
        self.assertEqual(get_provider({"ai": {"provider": "OpenAI_Compatible"}}), "openai_compatible")

    def test_required_env_var_fixed(self):
        self.assertEqual(required_env_var("gemini"), "GEMINI_API_KEY")
        self.assertEqual(required_env_var("deepseek"), "DEEPSEEK_API_KEY")

    def test_required_env_var_openai_compatible_default_and_override(self):
        self.assertEqual(required_env_var("openai_compatible"), "OPENAI_COMPATIBLE_API_KEY")
        self.assertEqual(
            required_env_var("openai_compatible", {"api_key_env": "CUSTOM_LLM_API_KEY"}),
            "CUSTOM_LLM_API_KEY",
        )

    def test_required_env_var_unknown(self):
        with self.assertRaises(ValueError):
            required_env_var("bogus")

    def test_api_key_required(self):
        self.assertFalse(api_key_required("openai_compatible"))
        for p in ("gemini", "openai", "anthropic", "deepseek"):
            self.assertTrue(api_key_required(p))


@unittest.skipUnless(HAS_LANGCHAIN_OPENAI, "langchain-openai not installed")
class TestOpenAICompatible(unittest.TestCase):
    def setUp(self):
        # Ensure ambient env vars don't leak into tests
        for var in ("OPENAI_COMPATIBLE_API_KEY", "CUSTOM_LLM_API_KEY", "OPENAI_API_KEY"):
            os.environ.pop(var, None)

    def test_builds_chatopenai_with_custom_base_url(self):
        cfg = make_config(
            {
                "model": "qwen3:14b",
                "base_url": "http://localhost:11434/v1",
                "temperature": 0.5,
                "max_tokens": 1234,
            }
        )
        llm = create_llm(cfg)
        self.assertEqual(type(llm).__name__, "ChatOpenAI")
        self.assertEqual(llm.model_name, "qwen3:14b")
        self.assertEqual(str(llm.openai_api_base), "http://localhost:11434/v1")

    def test_placeholder_key_when_env_unset(self):
        cfg = make_config({"model": "m", "base_url": "http://localhost:1/v1"})
        llm = create_llm(cfg)
        key = llm.openai_api_key
        secret = key.get_secret_value() if hasattr(key, "get_secret_value") else key
        self.assertEqual(secret, OPENAI_COMPATIBLE_PLACEHOLDER_KEY)

    def test_api_key_env_override(self):
        os.environ["CUSTOM_LLM_API_KEY"] = "test-key-123"
        cfg = make_config(
            {
                "model": "vendor/some-model",
                "base_url": "https://llm.example.com/v1",
                "api_key_env": "CUSTOM_LLM_API_KEY",
            }
        )
        llm = create_llm(cfg)
        key = llm.openai_api_key
        secret = key.get_secret_value() if hasattr(key, "get_secret_value") else key
        self.assertEqual(secret, "test-key-123")

    def test_default_base_url_is_ollama(self):
        cfg = make_config({"model": "m"})
        llm = create_llm(cfg)
        self.assertEqual(str(llm.openai_api_base), DEFAULT_OPENAI_COMPATIBLE_BASE_URL)

    def test_missing_model_raises(self):
        with self.assertRaises(ValueError) as ctx:
            create_llm(make_config({}))
        self.assertIn("openai_compatible.model", str(ctx.exception))

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            create_llm({"ai": {"provider": "bogus"}})

    def test_required_provider_missing_key_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                create_llm({"ai": {"provider": "openai", "openai": {"model": "gpt-4"}}})
            self.assertIn("OPENAI_API_KEY", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
