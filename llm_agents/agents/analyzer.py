from typing import Dict, List
from openai import OpenAI
import os
from rag.vectorstore import VulnerabilityKB
import json
import logging

logger = logging.getLogger(__name__)

class AnalyzerAgent:
    def __init__(self, kb: VulnerabilityKB):
        self.kb = kb
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def analyze(self, contract_info: Dict) -> Dict:
        """
        Perform a holistic analysis of the smart contract to detect vulnerabilities.
        """
        try:
            # 1. Extract contract information
            functions = contract_info.get("function_details", [])
            call_graph = contract_info.get("call_graph", {})

            # 2. Query KB with enhanced context
            query_results = self._get_relevant_vulnerabilities(functions, call_graph)

            # 3. Construct analysis prompt
            analysis_prompt = self._construct_analysis_prompt(contract_info, query_results)

            # 4. Get LLM analysis
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": analysis_prompt}
                ],
                temperature=0
            )

            # 5. Parse and validate response
            vulnerabilities = self._parse_vulnerability_response(
                response.choices[0].message.content
            )

            # 6. Enrich results with KB context
            enriched_results = self._enrich_results(vulnerabilities, query_results)

            return {"vulnerabilities": enriched_results}

        except Exception as e:
            logger.error(f"Error in vulnerability analysis: {str(e)}")
            return {"vulnerabilities": [], "error": str(e)}

    def _get_relevant_vulnerabilities(self, functions: List[Dict], call_graph: Dict) -> List[Dict]:
        """
        Query the knowledge base for relevant vulnerabilities based on contract features
        """
        # Construct feature-based queries
        queries = []

        # Query based on function characteristics
        for func in functions:
            func_query = f"""
            Analyze for vulnerabilities in function:
            - Name: {func['function']}
            - Visibility: {func['visibility']}
            - Parameters: {func['parameters']}
            - Returns: {func['returns']}
            """
            queries.append(func_query)

        # Query based on call graph patterns
        call_graph_query = f"Analyze call patterns for vulnerabilities: {json.dumps(call_graph)}"
        queries.append(call_graph_query)

        # Get results from KB for each query
        all_results = []
        for query in queries:
            results = self.kb.query_knowledge_base(query, k=3)
            all_results.extend(results)

        # Deduplicate and sort by relevance
        seen = set()
        unique_results = []
        for result in sorted(all_results, key=lambda x: x['relevance_score']):
            if result['name'] not in seen:
                seen.add(result['name'])
                unique_results.append(result)

        return unique_results

    def _construct_analysis_prompt(self, contract_info: Dict, kb_results: List[Dict]) -> str:
        """
        Construct detailed analysis prompt incorporating KB results
        """
        prompt = "Smart Contract Security Analysis\n\n"

        # 1. Contract Overview
        prompt += "Contract Functions:\n"
        for func in contract_info.get("function_details", []):
            prompt += f"""
Function: {func['function']}
Visibility: {func['visibility']}
Parameters: {func['parameters']}
Returns: {func['returns']}
---
"""

        # 2. Potential Vulnerabilities
        prompt += "\nPotential Vulnerability Patterns to Consider:\n"
        for result in kb_results:
            prompt += f"""
Vulnerability: {result['name']}
Description: {result['description']}
Impact: {result['impact']}
Relevant Pattern: {result['matching_chunk']}
---
"""

        # 3. Analysis Instructions
        prompt += """
Analyze the contract for these vulnerabilities considering:
1. Function interactions and call patterns
2. State variable modifications
3. External calls and their ordering
4. Access control mechanisms
5. Input validation and sanitization
"""

        return prompt

    def _get_system_prompt(self) -> str:
        """
        Define the system prompt for the LLM
        """
        return """You are an expert smart contract security auditor. Analyze the provided contract
        and identify potential vulnerabilities. For each vulnerability found, provide:
        1. Vulnerability type and classification
        2. Confidence score (0-1)
        3. Detailed technical reasoning
        4. Affected functions and components
        5. Potential impact and exploitation scenarios

        Output in strict JSON format:
        {
            "vulnerabilities": [
                {
                    "vulnerability_type": "string",
                    "confidence_score": float,
                    "reasoning": "string",
                    "affected_functions": ["string"],
                    "impact": "string",
                    "exploitation_scenario": "string"
                }
            ]
        }"""

    def _parse_vulnerability_response(self, response: str) -> List[Dict]:
        """
        Parse and validate LLM response, handling code block markers
        """
        try:
            # Clean the response by removing code block markers
            cleaned_response = response.strip()
            if cleaned_response.startswith("```"):
                # Remove opening code block
                cleaned_response = cleaned_response.split("\n", 1)[1]
            if cleaned_response.endswith("```"):
                # Remove closing code block
                cleaned_response = cleaned_response.rsplit("\n", 1)[0]
            # Remove any "json" language identifier
            cleaned_response = cleaned_response.replace("```json", "").replace("```", "")

            # Parse the cleaned JSON
            parsed = json.loads(cleaned_response)
            vulnerabilities = parsed.get("vulnerabilities", [])

            # Validate each vulnerability entry
            validated = []
            for vuln in vulnerabilities:
                if self._validate_vulnerability_entry(vuln):
                    validated.append(vuln)

            return validated
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {response}")
            logger.error(f"JSON decode error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error parsing response: {str(e)}")
            return []

    def _validate_vulnerability_entry(self, vuln: Dict) -> bool:
        """
        Validate vulnerability entry has required fields
        """
        required_fields = {
            "vulnerability_type": str,
            "confidence_score": float,
            "reasoning": str,
            "affected_functions": list
        }

        try:
            for field, field_type in required_fields.items():
                if field not in vuln or not isinstance(vuln[field], field_type):
                    return False
            return True
        except Exception:
            return False

    def _enrich_results(self, vulnerabilities: List[Dict], kb_results: List[Dict]) -> List[Dict]:
        """
        Enrich vulnerability results with KB context
        """
        enriched = []
        for vuln in vulnerabilities:
            # Find matching KB entry
            kb_match = next(
                (r for r in kb_results if r['name'].lower() == vuln['vulnerability_type'].lower()),
                None
            )

            if kb_match:
                vuln.update({
                    "kb_description": kb_match['description'],
                    "kb_impact": kb_match['impact'],
                    "prevention_measures": kb_match.get('prevention', []),
                    "exploit_template": kb_match['exploit_template']
                })

            enriched.append(vuln)

        return enriched
