# llm_agents/config.py
from typing import Dict, Optional, Tuple

class ModelConfig:
    """
    Configuration class for managing models and API settings across all agents.

    Attributes:
        analyzer_model (str): Model to use for the analyzer agent
        skeptic_model (str): Model to use for the skeptic agent
        exploiter_model (str): Model to use for the exploiter agent
        generator_model (str): Model to use for the generator agent
        base_url (str): Base URL for the OpenAI API (can be changed for proxies/alternatives)
        is_reasoning_model (Dict[str, bool]): Dictionary specifying which models support reasoning
        skip_poc_generation (bool): Whether to skip the PoC code generation step and stop at exploit plans
        export_markdown (bool): Whether to export the analysis report as a markdown file
    """

    def __init__(
        self,
        analyzer_model: str = "o3-mini",
        skeptic_model: str = "o3-mini",
        exploiter_model: str = "o3-mini",
        generator_model: str = "o3-mini",
        context_model: str = "o3-mini",
        base_url: Optional[str] = None,
        skip_poc_generation: bool = False,
        export_markdown: bool = False,
    ):
        self.analyzer_model = analyzer_model
        self.skeptic_model = skeptic_model
        self.exploiter_model = exploiter_model
        self.generator_model = generator_model
        self.context_model = context_model
        self.base_url = base_url
        self.skip_poc_generation = skip_poc_generation
        self.export_markdown = export_markdown

        # Define which models support reasoning-style prompts vs direct prompts
        self.is_reasoning_model = {
            # OpenAI models
            "o1-mini": True,
            "o3-mini": True,
            "gpt-4o": False,
            # Anthropic models
            "claude-3-5-haiku-latest": False,
            "claude-3-7-sonnet-latest": False,
            # DeepSeek models
            "deepseek-chat": False,
            "deepseek-reasoner": True,
        }

        # Define model provider mappings
        self.model_provider = {
            # OpenAI models
            "o1-mini": "openai",
            "o3-mini": "openai",
            "gpt-4o": "openai",
            # Anthropic models
            "claude-3-5-haiku-latest": "anthropic",
            "claude-3-7-sonnet-latest": "anthropic",
            # DeepSeek models
            "deepseek-chat": "deepseek",
            "deepseek-reasoner": "deepseek",
        }

        # Define provider base URLs
        self.provider_urls = {
            "openai": None,  # Default OpenAI URL
            "anthropic": "https://api.anthropic.com/v1/",
            "deepseek": "https://api.deepseek.com",
        }

    def get_model(self, agent_type: str) -> str:
        """
        Get the appropriate model for a specific agent.

        Args:
            agent_type (str): Type of agent ('analyzer', 'skeptic', 'exploiter', 'generator')

        Returns:
            str: Model name to use
        """
        if agent_type == "analyzer":
            return self.analyzer_model
        elif agent_type == "skeptic":
            return self.skeptic_model
        elif agent_type == "exploiter":
            return self.exploiter_model
        elif agent_type == "generator":
            return self.generator_model
        elif agent_type == "context":
            return self.context_model
        else:
            # Default to analyzer model if unknown agent type
            return self.analyzer_model

    def supports_reasoning(self, model_name: str) -> bool:
        """
        Check if a model supports reasoning-style prompts.

        Args:
            model_name (str): Name of the model

        Returns:
            bool: True if model supports reasoning, False otherwise
        """
        return self.is_reasoning_model.get(model_name, False)

    def get_provider_info(self, model_name: str) -> Tuple[str, str, str]:
        """
        Get information about the provider for a given model.

        Args:
            model_name (str): Name of the model

        Returns:
            Tuple[str, str, str]: (provider name, api key env var, base_url)
        """
        provider = self.model_provider.get(model_name, "openai")

        # Set the appropriate API key environment variable name
        if provider == "anthropic":
            api_key_env = "ANTHROPIC_API_KEY"
        elif provider == "deepseek":
            api_key_env = "DEEPSEEK_API_KEY"
        else:
            api_key_env = "OPENAI_API_KEY"

        # Get the base URL for this provider (or use the override if specified)
        base_url = self.base_url if self.base_url else self.provider_urls.get(provider)

        return provider, api_key_env, base_url

    def get_openai_args(self, model_name: str = None) -> Dict:
        """
        Get arguments for OpenAI client initialization.

        Args:
            model_name (str, optional): Name of the model to get args for

        Returns:
            Dict: Arguments to pass to OpenAI constructor
        """
        args = {}

        # If a model name is provided, get the base URL for its provider
        if model_name:
            _, _, provider_base_url = self.get_provider_info(model_name)
            if provider_base_url:
                args["base_url"] = provider_base_url
        # Otherwise use the config's base_url if provided
        elif self.base_url:
            args["base_url"] = self.base_url

        # args['extra_body'] = {
        #     "max_tokens": 64000,
        #     "thinking": { "type": "enabled", "budget_tokens": 2000 }
        # }

        return args
