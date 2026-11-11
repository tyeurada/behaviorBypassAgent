"""LLM provider factory.

Builds a LangChain chat model from `config.yaml`'s `ai:` section. The provider
is selected via `ai.provider` and each provider reads its own subsection
(`ai.gemini`, `ai.openai`, `ai.anthropic`, `ai.deepseek`).

API keys are always taken from environment variables, never from config.yaml:
    gemini            -> GEMINI_API_KEY
    openai            -> OPENAI_API_KEY
    anthropic         -> ANTHROPIC_API_KEY
    deepseek          -> DEEPSEEK_API_KEY
    openai_compatible -> env var named by ai.openai_compatible.api_key_env
                         (default OPENAI_COMPATIBLE_API_KEY; optional)

DeepSeek exposes an OpenAI-compatible API (https://api.deepseek.com), so it is
served through langchain-openai's ChatOpenAI with a custom base_url.

The `openai_compatible` provider covers any OpenAI-compatible endpoint:
- Hosted routers / gateways exposing the OpenAI chat-completions schema
- Local servers running open-weight models: Ollama (http://localhost:11434/v1),
  LM Studio (http://localhost:1234/v1), vLLM, llama.cpp, etc.
Local servers typically ignore the API key, so it may be left unset; a
placeholder string is sent in that case.
"""

import os

PROVIDER_ENV_VARS = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "openai_compatible": "OPENAI_COMPATIBLE_API_KEY",
}

DEFAULT_MODELS = {
    "gemini": "models/gemini-2.5-flash",
    "openai": "gpt-4",
    "anthropic": "claude-3-opus-20240229",
    "deepseek": "deepseek-chat",
    "openai_compatible": "",
}

DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_OPENAI_COMPATIBLE_BASE_URL = "http://localhost:11434/v1"  # Ollama

# Sent when an openai_compatible endpoint has no API key configured. Local
# servers (Ollama, LM Studio, llama.cpp) ignore the Authorization header.
OPENAI_COMPATIBLE_PLACEHOLDER_KEY = "no-api-key-required"

# Providers whose endpoint may not require authentication.
OPTIONAL_API_KEY_PROVIDERS = frozenset({"openai_compatible"})

_GEMINI_SAFETY_SETTINGS = None


def _gemini_safety_settings():
    global _GEMINI_SAFETY_SETTINGS
    if _GEMINI_SAFETY_SETTINGS is None:
        from langchain_google_genai import HarmBlockThreshold, HarmCategory

        _GEMINI_SAFETY_SETTINGS = {
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        }
    return _GEMINI_SAFETY_SETTINGS


def get_provider(config: dict) -> str:
    """Return the configured provider name (default: gemini)."""
    return (config.get("ai", {}) or {}).get("provider", "gemini").lower()


def required_env_var(provider: str, provider_cfg: dict | None = None) -> str:
    """Return the env var name holding the API key for a provider.

    For `openai_compatible`, the env var name can be overridden via the
    provider's `api_key_env` config field.
    """
    if provider not in PROVIDER_ENV_VARS:
        raise ValueError(f"Unknown AI provider: {provider}. Available: {sorted(PROVIDER_ENV_VARS)}")
    if provider == "openai_compatible" and provider_cfg:
        return provider_cfg.get("api_key_env") or PROVIDER_ENV_VARS[provider]
    return PROVIDER_ENV_VARS[provider]


def api_key_required(provider: str) -> bool:
    """Whether the provider cannot function without an API key env var."""
    return provider not in OPTIONAL_API_KEY_PROVIDERS


def create_llm(config: dict):
    """Instantiate the chat model for the configured provider.

    Args:
        config: Full parsed config.yaml dict.

    Returns:
        A LangChain BaseChatModel instance.

    Raises:
        ValueError: unknown provider or missing API key env var.
        ImportError: provider's langchain package is not installed.
    """
    ai_cfg = config.get("ai", {}) or {}
    provider = get_provider(config)
    provider_cfg = ai_cfg.get(provider, {}) or {}

    env_var = required_env_var(provider, provider_cfg)
    api_key = os.getenv(env_var)
    if not api_key and api_key_required(provider):
        raise ValueError(f"{env_var} not found in environment variables (provider={provider})")

    model = provider_cfg.get("model") or DEFAULT_MODELS[provider]
    temperature = provider_cfg.get("temperature", 0.7)
    max_tokens = provider_cfg.get("max_tokens")

    if provider == "gemini":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError as e:
            raise ImportError("langchain-google-genai is required for provider 'gemini'") from e
        kwargs = {
            "model": model,
            "google_api_key": api_key,
            "temperature": temperature,
            "top_p": provider_cfg.get("top_p", 0.9),
            "safety_settings": _gemini_safety_settings(),
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        return ChatGoogleGenerativeAI(**kwargs)

    if provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as e:
            raise ImportError("langchain-openai is required for provider 'openai'") from e
        kwargs = {"model": model, "api_key": api_key, "temperature": temperature}
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        return ChatOpenAI(**kwargs)

    if provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as e:
            raise ImportError("langchain-anthropic is required for provider 'anthropic'") from e
        kwargs = {
            "model": model,
            "api_key": api_key,
            "temperature": temperature,
            # Anthropic requires an explicit max_tokens; default generously.
            "max_tokens": max_tokens or 8192,
        }
        return ChatAnthropic(**kwargs)

    if provider == "deepseek":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as e:
            raise ImportError("langchain-openai is required for provider 'deepseek'") from e
        kwargs = {
            "model": model,
            "api_key": api_key,
            "base_url": provider_cfg.get("base_url") or DEFAULT_DEEPSEEK_BASE_URL,
            "temperature": temperature,
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        return ChatOpenAI(**kwargs)

    if provider == "openai_compatible":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as e:
            raise ImportError("langchain-openai is required for provider 'openai_compatible'") from e
        if not model:
            raise ValueError(
                "ai.openai_compatible.model is required "
                "(e.g. a local tag like 'qwen3:14b' "
                "or a hosted router id like 'vendor/model')"
            )
        kwargs = {
            "model": model,
            "api_key": api_key or OPENAI_COMPATIBLE_PLACEHOLDER_KEY,
            "base_url": provider_cfg.get("base_url") or DEFAULT_OPENAI_COMPATIBLE_BASE_URL,
            "temperature": temperature,
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        return ChatOpenAI(**kwargs)

    raise ValueError(f"Unsupported AI provider: {provider}")
