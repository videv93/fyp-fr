# ==============================
# File: llm_agents/agents/analyzer.py
# ==============================
from typing import Dict, List
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

    def analyze(self, contract_info: Dict) -> Dict:
        """
        Summarize the user's contract, retrieve known-vuln code,
        build a strict JSON prompt, parse response as JSON.
        """
        try:
            # 1) Build query for Pinecone
            print("QUERYING PINECONE")
            query_text = self._build_query_text(contract_info)
            relevant_docs = self.retriever.get_relevant_documents(query_text)

            # 2) Build the user + system messages
            system_prompt = (
                "You are an expert smart contract security auditor. "
                "You MUST respond with valid JSON and nothing else. "
                "No disclaimers, no extra text."
            )
            user_prompt = self._construct_analysis_prompt(contract_info, relevant_docs)
            print("PROMPT: ", user_prompt)

            # 3) Call LLM with system + user messages
            print("CALLING LLM")
            response_text = self._call_llm(system_prompt, user_prompt)
            logger.info(f"Raw LLM response:\n{response_text}")

            # 4) Parse JSON
            vulnerabilities = self._parse_llm_response(response_text)
            print("VULNERABILITIES: ", vulnerabilities)

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

    def _construct_analysis_prompt(self, contract_info: Dict, relevant_docs: List[Document]) -> str:
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
            summary += (
                f"- Function {fn['function']} (visibility={fn['visibility']}), calls={fn['called_functions']}\n"
            )

        # Add known vuln snippets
        snippet_text = "\n=== KNOWN VULNERABILITY SNIPPETS ===\n"
        for i, doc in enumerate(relevant_docs, start=1):
            meta = doc.metadata
            lines_range = f"{meta.get('start_line')} - {meta.get('end_line')}"
            cats = meta.get("vuln_categories", [])
            if not cats:
                continue
            snippet_text += f"[Snippet] {meta.get('filename','Unknown')} lines {lines_range} cats={cats}\n"
            snippet_text += doc.page_content[:1500]  # truncated to 1500 chars
            snippet_text += "\n\n"

        # The final instructions:
        instructions = """\
TASK:
1. Compare the known vulnerabilities above with the user contract summary.
2. Identify potential vulnerabilities in the user contract and fill the following JSON format:

{
  "vulnerabilities": [
    {
      "vulnerability_type": "...",
      "confidence_score": 0.0,
      "reasoning": "...",
      "affected_functions": ["..."],
      "impact": "...",
      "exploitation_scenario": "..."
    }
  ]
}

If you cannot determine any vulnerabilities, still produce a JSON with a single item
that says "vulnerability_type": "unknown", "confidence_score": 0, etc.

Important: Return ONLY valid JSON. No extra text.
"""

        full_prompt = contract + summary + snippet_text + instructions
        return full_prompt

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """
        Use openai.ChatCompletion with a system role to enforce JSON output.
        """
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0
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
            logger.error("LLM response not valid JSON, attempting fallback.\n" + response_text)
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
                    "exploitation_scenario": "unknown"
                }
            ]
