# llm_agents/agents/analyzer.py

from typing import Dict, List
from openai import OpenAI
import os
from rag.vectorstore import VulnerabilityKB

class AnalyzerAgent:
    def __init__(self, kb: VulnerabilityKB):
        self.kb = kb
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def analyze(self, contract_info: Dict) -> Dict:
        """
        Perform a holistic analysis of the smart contract to detect vulnerabilities.

        Args:
            contract_info (Dict): Contains 'function_details' and 'call_graph' of the contract.

        Returns:
            Dict: Contains a list of detected vulnerabilities with details.
        """
        # 1. Get all function details and call graph
        functions = contract_info.get("function_details", [])
        call_graph = contract_info.get("call_graph", {})

        # 2. Construct a comprehensive query for the entire contract
        query = self._construct_comprehensive_query(functions, call_graph)

        # Debugging
        # print("Comprehensive Query:", query)

        # 3. Query KB for relevant patterns
        relevant_docs = self.kb.query_knowledge_base(query, k=10)  # adjust k as needed

        # 4. Construct enhanced prompt with relevant docs
        prompt = self._construct_analysis_prompt(contract_info, relevant_docs)

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": """You are a smart contract security expert analyzing potential vulnerabilities in an entire contract.
                                                    Consider all functions, their interactions, and the control flow.
                                                    Pay special attention to:
                                                    1. State variable modifications
                                                    2. External calls
                                                    3. Control flow patterns
                                                    4. Access control mechanisms

                                                    Output your analysis strictly in JSON format as follows:

                                                    {
                                                        "vulnerabilities": [
                                                            {
                                                                "vulnerability_type": "Type of vulnerability",
                                                                "confidence_score": 0.95,
                                                                "reasoning": "Detailed reasoning for the vulnerability.",
                                                                "affected_functions": ["function1", "function2"]
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

        vulnerabilities = self._parse_vulnerability_response(response.choices[0].message.content)
        return {"vulnerabilities": vulnerabilities}

    def _construct_analysis_prompt(self, contract_info: Dict, relevant_docs: List) -> str:
        """
        Constructs the prompt for the language model by combining contract details and relevant KB documents.

        Args:
            contract_info (Dict): Contains 'function_details' and 'call_graph' of the contract.
            relevant_docs (List): List of relevant documents retrieved from the KB.

        Returns:
            str: The constructed prompt.
        """
        # Start with base contract info
        prompt = "Analyze the following smart contract for potential vulnerabilities:\n\n"

        # Add function details
        functions = contract_info.get("function_details", [])
        prompt += "Functions:\n"
        for func in functions:
            prompt += f"- {func['function']} ({func['visibility']})\n"
            prompt += f"  Parameters: {func['parameters']}\n"
            prompt += f"  Returns: {func['returns']}\n\n"

        # Add call graph
        prompt += f"\nCall Graph:\n{contract_info.get('call_graph', '')}\n\n"

        # Add relevant vulnerability patterns from KB
        prompt += "\nRelevant Vulnerability Patterns:\n"
        seen_patterns = set()  # To avoid duplicates
        for doc in relevant_docs:
            pattern_key = f"{doc.metadata['name']}_{doc.metadata['type']}"
            if pattern_key not in seen_patterns:
                prompt += f"Type: {doc.metadata['type']}\n"
                prompt += f"Name: {doc.metadata['name']}\n"
                prompt += f"Content: {doc.page_content}\n\n"
                seen_patterns.add(pattern_key)

        # Add specific instructions
        prompt += "\nAnalyze the contract for these potential vulnerabilities. For each vulnerability found, provide:\n"
        prompt += "1. Vulnerability Type\n"
        prompt += "2. Confidence Score (0-1)\n"
        prompt += "3. Detailed Reasoning\n"
        prompt += "4. Affected Functions\n"

        return prompt

    def _construct_comprehensive_query(self, functions: List[Dict], call_graph: Dict) -> str:
        """
        Constructs a comprehensive query based on all functions and the call graph.

        Args:
            functions (List[Dict]): List of function details.
            call_graph (Dict): Call graph of the contract.

        Returns:
            str: The comprehensive query.
        """
        query = "Smart Contract Analysis:\n\n"
        query += "Functions:\n"
        for func in functions:
            query += f"- Function Name: {func['function']}\n"
            query += f"  Visibility: {func['visibility']}\n"
            query += f"  Parameters: {', '.join([f'{ptype} {pname}' for ptype, pname in func['parameters']])}\n"
            query += f"  Returns: {', '.join([f'{rtype} {rname}' for rtype, rname in func['returns']])}\n\n"
        query += "Call Graph:\n"
        query += f"{call_graph}\n\n"
        query += "Vulnerability Patterns:\n"
        return query

    def _parse_vulnerability_response(self, response: str) -> List[Dict]:
        """
        Parses the GPT response into structured vulnerability data.

        Args:
            response (str): The raw response from GPT.

        Returns:
            List[Dict]: A list of vulnerabilities with details.
        """
        import json

        try:
            # Attempt to parse the response as JSON
            parsed_response = json.loads(response)
            vulnerabilities = parsed_response.get("vulnerabilities", [])
            return vulnerabilities
        except json.JSONDecodeError:
            # If JSON parsing fails, attempt to extract JSON from the response
            import re

            json_pattern = re.compile(r'\{.*\}', re.DOTALL)
            match = json_pattern.search(response)
            if match:
                try:
                    parsed_response = json.loads(match.group())
                    vulnerabilities = parsed_response.get("vulnerabilities", [])
                    return vulnerabilities
                except json.JSONDecodeError:
                    pass
            # Fallback in case of parsing errors
            return []
