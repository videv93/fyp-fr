# ==============================
# File: llm_agents/config.py
# ==============================
from typing import Dict, Optional

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
    """
    
    def __init__(
        self,
        analyzer_model: str = "o1-mini",
        skeptic_model: str = "o1-mini",
        exploiter_model: str = "o1-mini",
        generator_model: str = "o1-mini",
        base_url: Optional[str] = None,
    ):
        self.analyzer_model = analyzer_model
        self.skeptic_model = skeptic_model
        self.exploiter_model = exploiter_model
        self.generator_model = generator_model
        self.base_url = base_url
        
        # Define which models support reasoning-style prompts vs direct prompts
        self.is_reasoning_model = {
            # OpenAI models
            "gpt-3.5-turbo": True,
            "gpt-4": True,
            "gpt-4-turbo": True,
            "gpt-4o": True,
            # Anthropic models
            "claude-3-opus-20240229": True,
            "claude-3-sonnet-20240229": True,
            "claude-3-haiku-20240307": True,
            # Ollama models
            "o1-mini": False,
            "o1-preview": True,
            # Add more models as needed
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
    
    def get_openai_args(self) -> Dict:
        """
        Get arguments for OpenAI client initialization.
        
        Returns:
            Dict: Arguments to pass to OpenAI constructor
        """
        args = {}
        if self.base_url:
            args["base_url"] = self.base_url
        return args