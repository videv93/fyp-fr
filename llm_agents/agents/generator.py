# llm_agents/agents/generator.py

from typing import Dict, List
from openai import OpenAI
import os
import json
import re
from jsonschema import validate, ValidationError
from rag.vectorstore import VulnerabilityKB

# Define JSON schema for transaction sequences
TRANSACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "transactions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                    "value": {"type": "string"},
                    "data": {"type": "string"}
                },
                "required": ["from", "to", "value", "data"]
            }
        }
    },
    "required": ["transactions"]
}

class GeneratorAgent:
    def __init__(self, kb: VulnerabilityKB):
        self.kb = kb
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def generate(self, exploit_plan: Dict) -> List[Dict]:
        """
        Generate a sequence of transactions based on the exploit plan.

        Args:
            exploit_plan (Dict): The exploit plan containing setup, execution, and validation steps.

        Returns:
            List[Dict]: A list of transaction details.
        """
        prompt = self._construct_transaction_prompt(exploit_plan)

        response = self.client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """You are a smart contract exploit generator. Given an exploit plan, generate a sequence of transactions that can execute the exploit.

                                                Ensure the response is strictly in JSON format as follows:

                                                {
                                                    "transactions": [
                                                        {
                                                            "from": "0x...",
                                                            "to": "0x...",
                                                            "value": "0",
                                                            "data": "0x..."
                                                        },
                                                        ...
                                                    ]
                                                }

                                                Do not include any additional text outside of this JSON structure."""
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0
        )

        transactions = self._parse_transaction_response(response.choices[0].message.content)
        return transactions

    def _construct_transaction_prompt(self, exploit_plan: Dict) -> str:
        """
        Constructs the prompt for the LLM based on the exploit plan.

        Args:
            exploit_plan (Dict): The exploit plan containing setup, execution, and validation steps.

        Returns:
            str: The constructed prompt.
        """
        prompt = f"""
Based on the following exploit plan, generate a sequence of transactions to execute the exploit.

Exploit Plan:
Setup Steps:
{chr(10).join([f"{idx + 1}. {step}" for idx, step in enumerate(exploit_plan.get('setup_steps', []))])}

Execution Steps:
{chr(10).join([f"{idx + 1}. {step}" for idx, step in enumerate(exploit_plan.get('execution_steps', []))])}

Validation Steps:
{chr(10).join([f"{idx + 1}. {step}" for idx, step in enumerate(exploit_plan.get('validation_steps', []))])}

Provide the transactions in the following JSON format:

{{
    "transactions": [
        {{
            "from": "0x...",
            "to": "0x...",
            "value": "0",
            "data": "0x..."
        }},
        ...
    ]
}}
"""
        return prompt

    def _parse_transaction_response(self, response: str) -> List[Dict]:
        """
        Parses the LLM response into a structured list of transactions using JSON schema validation.

        Args:
            response (str): The raw response from the LLM.

        Returns:
            List[Dict]: A list of transaction details.
        """
        try:
            # Attempt to parse the response as JSON
            parsed_response = json.loads(response)
            # Validate against schema
            validate(instance=parsed_response, schema=TRANSACTION_SCHEMA)
            transactions = parsed_response.get("transactions", [])
            return transactions
        except json.JSONDecodeError:
            # Attempt to extract JSON from the response
            json_pattern = re.compile(r'\{.*\}', re.DOTALL)
            match = json_pattern.search(response)
            if match:
                try:
                    parsed_response = json.loads(match.group())
                    validate(instance=parsed_response, schema=TRANSACTION_SCHEMA)
                    transactions = parsed_response.get("transactions", [])
                    return transactions
                except (json.JSONDecodeError, ValidationError):
                    pass
            # Fallback in case of parsing errors
            print("Failed to parse transaction response.")
            return []
