# ==============================
# File: llm_agents/agents/analyzer.py
# ==============================
from typing import Dict, List
from pathlib import Path
import json
import logging
import os

from openai import OpenAI
from langchain.schema import Document

logger = logging.getLogger(__name__)


class AnalyzerAgent:
    def __init__(self, retriever, model_name="gpt-4o"):
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
        """
        Summarize the user's contract, retrieve known-vuln code,
        build a strict JSON prompt, parse response as JSON.
        """
        try:
            # 1) Build query for Pinecone
            print("QUERYING Pinecone")
            query_text = self._build_query_text(contract_info)
            relevant_docs = self.retriever.invoke(contract_info["source_code"])
            print("Found", len(relevant_docs), "relevant snippets")
            # print(relevant_docs)
            # 2) Build the user + system messages
            system_prompt = (
                "You are an expert smart contract security auditor. "
                "You MUST respond with valid JSON and nothing else. "
                "No disclaimers, no extra text."
            )
            user_prompt = self._construct_analysis_prompt(contract_info, relevant_docs)

            # 3) Call LLM with system + user messages
            print("CALLING Analyzer Agent")
            response_text = self._call_llm(system_prompt, user_prompt)

            # 4) Parse JSON
            vulnerabilities = self._parse_llm_response(response_text)

            return {"vulnerabilities": vulnerabilities}

        except Exception as e:
            logger.error(f"AnalyzerAgent error: {str(e)}")
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
        This summary extracts key 'description' fields from the findings.
        """
        summary_lines = []

        def process_item(item):
            if isinstance(item, dict):
                # If there is a description field, add it (avoid duplicates)
                desc = item.get("description")
                if desc:
                    clean_desc = desc.strip().replace("\n", " ")
                    if clean_desc not in summary_lines:
                        summary_lines.append(clean_desc)
                # Also process any nested lists or dicts inside this dict
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
        We keep it simpler. We'll provide the user contract summary, and
        relevant known vulnerability docs. Then we instruct the LLM to produce JSON only.
        """
        # Contract Source Code
        contract = "\n=== CONTRACT SOURCE CODE ===\n"
        contract += contract_info.get("source_code", "N/A")

        # Summarize user contract
        summary = "=== USER CONTRACT SUMMARY ===\n"
        for fn in contract_info.get("function_details", []):
            summary += f"- Function {fn['function']} (visibility={fn['visibility']}), calls={fn['called_functions']}\n"

        # Add known vulnerability snippets from the retriever
        snippet_text = "\n=== KNOWN VULNERABILITY SNIPPETS ===\n"
        for i, doc in enumerate(relevant_docs, start=1):
            meta = doc.metadata
            lines_range = f"{meta.get('start_line')} - {meta.get('end_line')}"
            cats = meta.get("vuln_categories", [])
            snippet_text += f"[Snippet] {meta.get('filename','Unknown')} lines {lines_range} cats={cats}\n"
            snippet_text += doc.page_content[:1500]  # truncated to 1500 chars
            snippet_text += "\n\n"

        # Append the detector results insights (if available)
        detector_section = ""
        if "detector_results" in contract_info:
            detector_section = self._summarize_detector_results(
                contract_info["detector_results"]
            )

        # Category guidance section
        category_guidance = "\n=== VULNERABILITY CATEGORY GUIDANCE ===\n"
        all_categories = self.vuln_categories.keys()
        snippet_categories = set()
        for doc in relevant_docs:
            snippet_categories.update(doc.metadata.get("vuln_categories", []))
        for cat in all_categories:
            guidance = self.vuln_categories[cat]
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

        # Update system prompt
        system_prompt = (
            "You are an expert smart contract security auditor. You MUST:\n"
            "1. Check for ALL these vulnerability categories:\n"
            + "\n".join([f"- {cat}" for cat in all_categories])
            + "\n2. Pay SPECIAL ATTENTION to categories marked 'HIGH PRIORITY' that match known vulnerabilities\n"
            "3. Follow detection strategies exactly\n"
            "4. Return valid JSON with EXACT category names\n"
            "5. Never invent new categories outside the provided list"
        )

        # Task instructions
        instructions = """\
TASK:
1. Systematically check for ALL vulnerability categories below.
2. For HIGH PRIORITY categories (those with matching examples):
   - Compare directly with similar code patterns.
   - Apply detection strategies rigorously.
3. For other categories:
   - Perform brief checks based on detection strategies.
4. Format findings as:

{
  "vulnerabilities": [{
      "vulnerability_type": "EXACT_CATEGORY_NAME",
      "confidence_score": 0.0-1.0,
      "reasoning": "Specific pattern match and analysis steps",
      "affected_functions": ["..."],
      "impact": "...",
      "exploitation_scenario": "..."
  }]
}
"""
        # Build the full prompt by concatenating sections
        full_prompt = (
            contract
            + summary
            + category_guidance
            + snippet_text
            + detector_section
            + instructions
        )
        return full_prompt

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """
        Use openai.ChatCompletion with a system role to enforce JSON output.
        """
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
        )
        return resp.choices[0].message.content.strip()

    def _parse_llm_response(self, response_text: str) -> List[Dict]:
        """
        Attempt to parse the LLM's response as JSON. If it fails,
        try to look for code blocks containing JSON.
        """
        try:
            return json.loads(response_text).get("vulnerabilities", [])
        except json.JSONDecodeError:
            logger.error(
                "LLM response not valid JSON, attempting fallback.\n" + response_text
            )
            # fallback attempt: search for triple backtick code blocks
            import re

            match = re.search(r"```(?:json)?(.*?)```", response_text, re.DOTALL)
            if match:
                block = match.group(1).strip()
                try:
                    return json.loads(block).get("vulnerabilities", [])
                except:
                    pass

            # final fallback => return a single “unknown”
            return [
                {
                    "vulnerability_type": "unknown",
                    "confidence_score": 0.0,
                    "reasoning": "LLM did not produce valid JSON or no code. Fallback used.",
                    "affected_functions": [],
                    "impact": "unknown",
                    "exploitation_scenario": "unknown",
                }
            ]
