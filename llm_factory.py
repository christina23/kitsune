"""
LLM Factory for creating language model instances
"""

import os
from typing import Dict, Optional
from langchain_core.language_models import BaseChatModel
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI

from models import LLMProvider
from config import LLMConfig


class LLMFactory:
    """Factory for creating LLM instances"""
    
    def __init__(
        self,
        default_provider: Optional[str] = None,
        api_keys: Optional[Dict[str, str]] = None,
    ):
        self.default_provider = (
            default_provider or os.getenv("LLM_PROVIDER", "openai")
        )
        self.api_keys = api_keys or {}
        self._validate_environment()

    def _validate_environment(self):
        """Validate that required API keys are present"""
        provider = LLMProvider(self.default_provider)
        config = LLMConfig.DEFAULTS[provider]
        api_key = self._get_api_key(provider)
        if not api_key:
            print(
                f"Warning: {config['api_key_env']} not found"
                " in environment or api_keys dict"
            )

    def _get_api_key(self, provider: LLMProvider) -> Optional[str]:
        """Get API key for a provider"""
        if provider.value in self.api_keys:
            return self.api_keys[provider.value]
        config = LLMConfig.DEFAULTS.get(provider)
        if config and "api_key_env" in config:
            return os.getenv(config["api_key_env"])
        return None

    def create_model(
        self,
        provider: Optional[str] = None,
        model_name: Optional[str] = None,
        temperature: float = 0,
        api_key: Optional[str] = None,
        **kwargs,
    ) -> BaseChatModel:
        """Create an LLM instance for the specified provider"""
        provider = provider or self.default_provider
        provider_enum = LLMProvider(provider.lower())
        config = LLMConfig.DEFAULTS[provider_enum]
        model = model_name or config.get("model")
        final_api_key = api_key or self._get_api_key(provider_enum)

        if provider_enum == LLMProvider.ANTHROPIC:
            # Fix for Anthropic: Use newer model and add retry logic
            anthropic_model = model
            if model == "claude-3-5-sonnet-20241022":
                # Use Claude Sonnet 4 model string
                anthropic_model = "claude-sonnet-4-20250514"

            return ChatAnthropic(
                model=anthropic_model,
                anthropic_api_key=final_api_key,
                temperature=temperature,
                max_tokens=kwargs.pop(
                    "max_tokens", config.get("max_tokens", 4096)
                ),
                **kwargs,
            )
        elif provider_enum == LLMProvider.OPENAI:
            return ChatOpenAI(
                model=model,
                api_key=final_api_key,
                temperature=temperature,
                max_tokens=kwargs.pop(
                    "max_tokens", config.get("max_tokens", 4096)
                ),
                **kwargs,
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")