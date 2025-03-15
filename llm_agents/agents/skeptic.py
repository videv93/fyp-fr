# ==============================
# File: llm_agents/agents/skeptic.py
# ==============================
import os
import json
from openai import OpenAI
import re
from utils.print_utils import create_progress_spinner, print_warning

class SkepticAgent:
    """
    The SkepticAgent re-checks each vulnerability to confirm whether it truly applies.
    It outputs a re-ranked or filtered list of vulnerabilities, sorted from highest to lowest confidence.
    """

    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def audit_vulnerabilities(self, contract_source: str, vulnerabilities: list) -> list:
        if not vulnerabilities:
            return []

        with create_progress_spinner("Re-checking vulnerabilities") as progress:
            task = progress.add_task("Analyzing...")

            # Build prompts
            system_prompt = """You are a strict, detail-oriented Smart Contract Security Auditor.
    You are given a contract's source code and an alleged set of vulnerabilities.
    For each alleged vulnerability, decide:
      1) Is it likely real or a false positive?
      2) Give a confidence score from 0.0 to 1.0. (0.0 = false positive, 1.0 = real)
      3) Provide a short justification.

    Output JSON exactly in the format:
    {
      "rechecked_vulnerabilities": [
        {
          "original_idx": 0,
          "skeptic_confidence": 0.0,
          "validity_reasoning": ""
        },
        ...
      ]
    }
            """
            user_prompt = f"=== CONTRACT SOURCE CODE ===\n{contract_source}\n\n=== REPORTED VULNERABILITIES ===\n"
            for idx, vuln in enumerate(vulnerabilities):
                user_prompt += f"#{idx} => type={vuln.get('vulnerability_type')} code:\n"
                code_snippet = vuln.get("code_snippet") or "(no snippet)"
                user_prompt += f"{code_snippet}\n\n"

            user_prompt += """Please re-check each vulnerability from #0, #1, #2, etc.
    Return a JSON object with the final verdict.
    """
            # Call LLM
            response = self.client.chat.completions.create(
                model="o1-mini",
                messages=[{"role": "user", "content": system_prompt + user_prompt}],
            )
            text_out = response.choices[0].message.content.strip()

            # Parse results
            progress.update(task, description="Processing results...")
            rechecked = self._parse_response(text_out)

            # Update vulnerabilities with skeptic results
            for item in rechecked:
                idx = item.get("original_idx")
                if idx is not None and 0 <= idx < len(vulnerabilities):
                    vulnerabilities[idx]["skeptic_confidence"] = item.get(
                        "skeptic_confidence", 0.0
                    )
                    vulnerabilities[idx]["validity_reasoning"] = item.get(
                        "validity_reasoning", ""
                    )


            progress.update(task, completed=True)

        return sorted(vulnerabilities, key=lambda x: x.get("skeptic_confidence", 0), reverse=True)

    def _parse_response(self, text_out: str) -> list:
        try:
            data = json.loads(text_out)
            return data.get("rechecked_vulnerabilities", [])
        except json.JSONDecodeError:
            # Try extracting JSON from markdown code block
            if match := re.search(r"```(?:json)?(.*?)```", text_out, re.DOTALL):
                try:
                    return json.loads(match.group(1).strip()).get("rechecked_vulnerabilities", [])
                except:
                    print_warning("Failed to parse JSON from code block")
            return []
