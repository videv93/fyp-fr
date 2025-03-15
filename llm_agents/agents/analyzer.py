# ==============================
# File: llm_agents/agents/analyzer.py
# ==============================
from typing import Dict, List
from pathlib import Path
import json
import logging
import os
from utils.print_utils import print_step, print_warning, create_progress_spinner
from openai import OpenAI
from langchain.schema import Document

logger = logging.getLogger(__name__)


class AnalyzerAgent:
    def __init__(self, retriever, model_name="o1-mini"):
        self.retriever = retriever
        self.model_name = model_name
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        # Load vulnerability categories
        self.vuln_categories = self._load_vuln_categories()

    def _load_vuln_categories(self):
        """Load vulnerability category definitions"""
        categories_path = (
            Path(__file__).parent.parent.parent / "vulnerability_categories.json"
        )
        with open(categories_path, "r") as f:
            data = json.load(f)
        return data["categories"]

    def analyze(self, contract_info: Dict) -> Dict:
        try:
            with create_progress_spinner("Analyzing contract vulnerabilities") as progress:
                task = progress.add_task("Searching for vulnerability patterns...")
                query_text = self._build_query_text(contract_info)
                relevant_docs = self.retriever.invoke(contract_info["source_code"])
                progress.update(task, description=f"Found {len(relevant_docs)} relevant patterns")

                # Build prompts
                progress.update(task, description="Constructing analysis prompt...")

                all_categories = self.vuln_categories.keys()
                system_prompt = (
                    "You are an expert smart contract security auditor. You MUST:\n"
                    "1. Check for ALL these vulnerability categories:\n"
                    "2. You should also check for any other vulnerabilities that may arise based on flaws in business logic.\n"
                    + "\n".join([f"- {cat}" for cat in all_categories])
                    + "\n3. Pay SPECIAL ATTENTION to categories marked 'HIGH PRIORITY' that match known vulnerabilities\n"
                    "4. Use detection strategies as a guide\n"
                    "5. Return valid JSON with EXACT category names\n"
                )
                user_prompt = self._construct_analysis_prompt(contract_info, relevant_docs)

                # Call LLM
                progress.update(task, description="Analyzing with LLM...")
                response_text = self._call_llm(system_prompt, user_prompt)

                # Parse results
                progress.update(task, description="Processing results...")
                vulnerabilities = self._parse_llm_response(response_text)
                self._attach_code_snippets(vulnerabilities, contract_info)

                progress.update(task, completed=True)

            return {"vulnerabilities": vulnerabilities}

        except Exception as e:
            print_warning(f"Analysis error: {str(e)}")
            return {"vulnerabilities": [], "error": str(e)}

    def _build_query_text(self, contract_info: Dict) -> str:
        """Small summary of the user’s contract to retrieve related vulnerabilities."""
        lines = []
        for fn in contract_info.get("function_details", []):
            lines.append(f"Function {fn['function']} calls {fn['called_functions']}")
        return "\n".join(lines)

    def _summarize_detector_results(self, detector_results) -> str:
        """
        Traverse the nested detector_results structure and return a bullet-point summary.
        Extract key 'description' fields from the findings.
        """
        summary_lines = []

        def process_item(item):
            if isinstance(item, dict):
                desc = item.get("description")
                if desc:
                    clean_desc = desc.strip().replace("\n", " ")
                    if clean_desc not in summary_lines:
                        summary_lines.append(clean_desc)
                for value in item.values():
                    process_item(value)
            elif isinstance(item, list):
                for sub_item in item:
                    process_item(sub_item)

        process_item(detector_results)
        if summary_lines:
            bullet_points = "\n".join(f"- {line}" for line in summary_lines)
            return f"\n=== SLITHER DETECTOR INSIGHTS ===\n{bullet_points}\n"
        else:
            return (
                "\n=== SLITHER DETECTOR INSIGHTS ===\nNo issues detected by Slither.\n"
            )

    def _construct_analysis_prompt(
        self, contract_info: Dict, relevant_docs: List[Document]
    ) -> str:
        """
        We'll provide the user contract summary, known vulnerability docs,
        plus the slither detector results, then request JSON.
        """
        contract = "\n=== CONTRACT SOURCE CODE ===\n"
        contract += contract_info.get("source_code", "N/A")

        # Summarize user contract
        summary = "=== USER CONTRACT SUMMARY ===\n"
        for fn in contract_info.get("function_details", []):
            summary += f"- Function {fn['function']} (visibility={fn['visibility']}), calls={fn['called_functions']}\n"

        # Add known vulnerability snippets
        snippet_text = "\n=== KNOWN VULNERABILITY SNIPPETS ===\n"
        for i, doc in enumerate(relevant_docs, start=1):
            meta = doc.metadata
            lines_range = f"{meta.get('start_line')} - {meta.get('end_line')}"
            cats = meta.get("vuln_categories", [])
            if cats:
                snippet_text += f"[Snippet] {meta.get('filename','Unknown')} lines {lines_range} cats={cats}\n"
                snippet_text += doc.page_content[:1500]  # truncated
                snippet_text += "\n\n"

        # Slither results
        detector_section = ""
        if "detector_results" in contract_info:
            detector_section = self._summarize_detector_results(
                contract_info["detector_results"]
            )

        # Category guidance
        category_guidance = "\n=== VULNERABILITY CATEGORY GUIDANCE ===\n"
        snippet_categories = set()
        for doc in relevant_docs:
            snippet_categories.update(doc.metadata.get("vuln_categories", []))

        for cat, guidance in self.vuln_categories.items():
            priority_note = (
                " (HIGH PRIORITY - MATCHES KNOWN VULNERABILITIES)"
                if cat in snippet_categories
                else ""
            )
            category_guidance += (
                f"## {cat.upper()}{priority_note} ##\n"
                f"Description: {guidance['description']}\n"
                f"Common Patterns:\n- "
                + "\n- ".join(guidance["common_patterns"])
                + "\n"
                f"Detection Strategy: {guidance['detection_strategy']}\n\n"
            )

        # Task instructions
        instructions = """\
TASK:
1. Systematically check for ALL vulnerability categories specified.
2. Systematically check for any other vulnerabilities that may arise due to BUSINESS LOGIC.
2. Mark categories as (HIGH PRIORITY) if code matches known patterns.
3. Return all discovered vulnerabilities in the JSON. Do not omit.
4. Format findings as:

{
  "vulnerabilities": [{
      "vulnerability_type": "EXACT_CATEGORY_NAME",
      "confidence_score": 0.0-1.0,
      "reasoning": "Specific pattern match and analysis steps",
      "affected_functions": ["..."],
      "impact": "...",
      "exploitation_scenario": "..."
  }, ...]
}
"""

        full_prompt = (
            contract
            + summary
            + category_guidance
            + snippet_text
            + detector_section
            + "\n"
            + instructions
        )
        return full_prompt

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """
        Use openai.ChatCompletion with a single big user message
        (you can do system+user if you wish).
        """
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "user", "content": system_prompt + "\n\n" + user_prompt},
            ],
        )
        return resp.choices[0].message.content.strip()

    def _parse_llm_response(self, response_text: str) -> List[Dict]:
        """
        Attempt to parse the LLM's response as JSON.
        Fallback to searching for code blocks if raw parse fails.
        """
        import re

        try:
            data = json.loads(response_text)
            return data.get("vulnerabilities", [])
        except json.JSONDecodeError:
            # fallback: search for triple backtick blocks
            match = re.search(r"```(?:json)?(.*?)```", response_text, re.DOTALL)
            if match:
                block = match.group(1).strip()
                try:
                    data = json.loads(block)
                    return data.get("vulnerabilities", [])
                except:
                    pass
            # ultimate fallback
            return [
                {
                    "vulnerability_type": "unknown",
                    "confidence_score": 0.0,
                    "reasoning": "No valid JSON found",
                    "affected_functions": [],
                    "impact": "",
                    "exploitation_scenario": "",
                }
            ]

    def _attach_code_snippets(self, vulnerabilities: list, contract_info: dict):
        """
        Attach code snippets to vulnerability entries. This function handles both:
        1. Direct matches from function details when source_mapping.content is available
        2. Fallback to searching in source code when direct matches aren't found
        """
        # Create a map of function names to their code content
        fn_map = {}
        for fn_detail in contract_info.get("function_details", []):
            function_name = fn_detail["function"]
            content = fn_detail.get("content")
            if content:  # Only add if content is not None or empty
                fn_map[function_name] = content
            # Handle fully qualified function names with contract prefixes
            qualified_name = f"{fn_detail['contract']}.{function_name}"
            if content:
                fn_map[qualified_name] = content

        # Extract code for affected functions
        for vuln in vulnerabilities:
            snippet_list = []
            affected_fns = vuln.get("affected_functions", [])
            
            # First try direct matches from function map
            for fn_name in affected_fns:
                if code_snip := fn_map.get(fn_name):
                    snippet_list.append(code_snip)
            
            # Set the code snippet
            if snippet_list:
                vuln["code_snippet"] = "\n\n".join(snippet_list)
            else:
                # Try to search for relevant code from source code directly if no matches are found
                source_code = contract_info.get("source_code", "")
                if source_code and affected_fns:
                    for fn_name in affected_fns:
                        # Extract function name without contract prefix
                        simple_fn_name = fn_name.split('.')[-1] if '.' in fn_name else fn_name
                        
                        # Find in source code directly - basic approach
                        lines = source_code.split('\n')
                        for i, line in enumerate(lines):
                            # Look for function declaration with the name
                            if f"function {simple_fn_name}" in line:
                                # Found function declaration, extract surrounding content
                                start = max(0, i-1)
                                end = min(len(lines), i+15)  # Get ~15 lines of context
                                vuln["code_snippet"] = "\n".join(lines[start:end])
                                break
                        else:
                            continue  # Try next function name if this one wasn't found
                        break  # Exit if we found at least one function
                    else:
                        # If no functions were found after searching all
                        vuln["code_snippet"] = "(No matching function code found)"
                else:
                    vuln["code_snippet"] = "(No matching function code found)"
