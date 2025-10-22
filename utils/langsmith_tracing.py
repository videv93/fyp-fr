# utils/langsmith_tracing.py
import os
from functools import wraps
from langsmith import traceable
from langsmith.run_helpers import get_current_run_tree

def setup_langsmith():
    """
    Setup LangSmith tracing. Call this once at startup.
    Reads configuration from environment variables.

    Environment Variables:
        LANGCHAIN_TRACING_V2: Set to 'true' to enable tracing
        LANGCHAIN_API_KEY: Your LangSmith API key
        LANGCHAIN_PROJECT: Project name for organizing traces (default: 'smartguard-audit')
        LANGCHAIN_ENDPOINT: LangSmith API endpoint (default: 'https://api.smith.langchain.com')

    Returns:
        bool: True if tracing is enabled, False otherwise
    """
    # Check if tracing is enabled
    if os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true":
        api_key = os.getenv("LANGCHAIN_API_KEY")
        if not api_key:
            print("⚠ LangSmith tracing enabled but LANGCHAIN_API_KEY not set")
            return False

        print("✓ LangSmith tracing enabled")
        project = os.getenv("LANGCHAIN_PROJECT", "smartguard-audit")
        endpoint = os.getenv("LANGCHAIN_ENDPOINT", "https://api.smith.langchain.com")
        print(f"  Project: {project}")
        print(f"  Endpoint: {endpoint}")
        print(f"  View traces at: https://smith.langchain.com/")
        return True
    else:
        print("✗ LangSmith tracing disabled")
        print("  To enable: set LANGCHAIN_TRACING_V2=true in .env")
        return False

def trace_agent_call(agent_name):
    """
    Decorator to trace agent LLM calls with LangSmith.

    This decorator automatically logs:
    - Input prompts (system and user messages)
    - Model responses
    - Token usage
    - Execution time
    - Agent and model metadata

    Args:
        agent_name (str): Name of the agent (e.g., 'analyzer', 'skeptic', 'exploiter')

    Usage:
        @trace_agent_call("analyzer")
        def _call_llm(self, system_prompt, user_prompt):
            # ... your OpenAI API call ...
            return response_text

    Example:
        In analyzer.py:

        from utils.langsmith_tracing import trace_agent_call

        class AnalyzerAgent:
            @trace_agent_call("analyzer")
            def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
                # Existing code stays the same
                resp = self.client.chat.completions.create(...)
                return resp.choices[0].message.content
    """
    def decorator(func):
        @traceable(
            name=f"{agent_name}_llm_call",
            run_type="llm",
            tags=[agent_name, "smartguard", "vulnerability-analysis"]
        )
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Add metadata to the trace
            run_tree = get_current_run_tree()
            if run_tree:
                metadata = {
                    "agent": agent_name,
                }

                # Add model name if available
                if hasattr(self, 'model_name'):
                    metadata["model"] = self.model_name

                # Add prompt info from args if available
                if len(args) >= 1:
                    metadata["system_prompt_length"] = len(str(args[0]))
                if len(args) >= 2:
                    metadata["user_prompt_length"] = len(str(args[1]))

                run_tree.extra = metadata

            # Call the original function
            result = func(self, *args, **kwargs)

            # Add response metadata
            if run_tree and result:
                if not run_tree.outputs:
                    run_tree.outputs = {}
                run_tree.outputs["response_length"] = len(str(result))

            return result

        return wrapper
    return decorator
