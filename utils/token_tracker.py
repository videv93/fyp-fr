"""
Token usage tracking utility for LLM API calls.
"""
from typing import Dict, List, Optional
import json
from datetime import datetime

class TokenTracker:
    """
    Token usage tracker for OpenAI and other LLM API calls.
    Tracks prompt tokens, completion tokens, and total tokens used
    by different components of the system.
    """

    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset all token counts."""
        self.usage_by_agent = {}
        self.usage_by_model = {}
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.call_count = 0
        self.run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    def log_tokens(self, 
                  agent_name: str, 
                  model_name: str, 
                  prompt_tokens: int, 
                  completion_tokens: int, 
                  total_tokens: int):
        """
        Log token usage for a specific agent and model.
        
        Args:
            agent_name: Name of the agent making the call
            model_name: Name of the model used
            prompt_tokens: Number of tokens in the prompt
            completion_tokens: Number of tokens in the completion
            total_tokens: Total number of tokens used
        """
        # Update agent-specific counts
        if agent_name not in self.usage_by_agent:
            self.usage_by_agent[agent_name] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "call_count": 0
            }
        
        self.usage_by_agent[agent_name]["prompt_tokens"] += prompt_tokens
        self.usage_by_agent[agent_name]["completion_tokens"] += completion_tokens
        self.usage_by_agent[agent_name]["total_tokens"] += total_tokens
        self.usage_by_agent[agent_name]["call_count"] += 1
        
        # Update model-specific counts
        if model_name not in self.usage_by_model:
            self.usage_by_model[model_name] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "call_count": 0
            }
        
        self.usage_by_model[model_name]["prompt_tokens"] += prompt_tokens
        self.usage_by_model[model_name]["completion_tokens"] += completion_tokens
        self.usage_by_model[model_name]["total_tokens"] += total_tokens
        self.usage_by_model[model_name]["call_count"] += 1
        
        # Update total counts
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_tokens += total_tokens
        self.call_count += 1
    
    def get_usage_summary(self) -> Dict:
        """
        Get a summary of token usage.
        
        Returns:
            Dictionary with token usage summary
        """
        return {
            "by_agent": self.usage_by_agent,
            "by_model": self.usage_by_model,
            "total": {
                "prompt_tokens": self.total_prompt_tokens,
                "completion_tokens": self.total_completion_tokens,
                "total_tokens": self.total_tokens,
                "call_count": self.call_count
            },
            "timestamp": self.run_timestamp
        }
    
    def save_to_file(self, filepath: Optional[str] = None) -> str:
        """
        Save token usage stats to a JSON file.
        
        Args:
            filepath: Optional path to save the file. If not provided,
                     a default path will be used.
                     
        Returns:
            Path where the file was saved
        """
        if filepath is None:
            filepath = f"token_usage_{self.run_timestamp}.json"
        
        with open(filepath, 'w') as f:
            json.dump(self.get_usage_summary(), f, indent=2)
        
        return filepath
    
    def print_summary(self, include_models: bool = True, include_agents: bool = True):
        """
        Print a formatted summary of token usage.
        
        Args:
            include_models: Whether to include per-model breakdown
            include_agents: Whether to include per-agent breakdown
        """
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        # Print total usage
        console.print("\n[bold blue]===== Token Usage Summary =====[/bold blue]")
        console.print(f"Total API Calls: [bold]{self.call_count}[/bold]")
        console.print(f"Total Tokens: [bold]{self.total_tokens:,}[/bold] " +
                     f"(Prompt: {self.total_prompt_tokens:,}, " +
                     f"Completion: {self.total_completion_tokens:,})")
        
        # Print agent-specific usage
        if include_agents and self.usage_by_agent:
            console.print("\n[bold]Token Usage by Agent:[/bold]")
            agent_table = Table(show_header=True)
            agent_table.add_column("Agent")
            agent_table.add_column("Calls")
            agent_table.add_column("Prompt Tokens")
            agent_table.add_column("Completion Tokens")
            agent_table.add_column("Total Tokens")
            
            for agent, usage in self.usage_by_agent.items():
                agent_table.add_row(
                    agent,
                    str(usage["call_count"]),
                    f"{usage['prompt_tokens']:,}",
                    f"{usage['completion_tokens']:,}",
                    f"{usage['total_tokens']:,}"
                )
            
            console.print(agent_table)
        
        # Print model-specific usage
        if include_models and self.usage_by_model:
            console.print("\n[bold]Token Usage by Model:[/bold]")
            model_table = Table(show_header=True)
            model_table.add_column("Model")
            model_table.add_column("Calls")
            model_table.add_column("Prompt Tokens")
            model_table.add_column("Completion Tokens")
            model_table.add_column("Total Tokens")
            
            for model, usage in self.usage_by_model.items():
                model_table.add_row(
                    model,
                    str(usage["call_count"]),
                    f"{usage['prompt_tokens']:,}",
                    f"{usage['completion_tokens']:,}",
                    f"{usage['total_tokens']:,}"
                )
            
            console.print(model_table)
        
        console.print("[dim]Token usage stats have been recorded for this run.[/dim]")


# Global instance for use throughout the application
token_tracker = TokenTracker()
