# ==============================
# File: llm_agents/agent_coordinator.py
# ==============================
from typing import Dict

# Import the new function
from rag.doc_db import get_vuln_retriever_from_json

# CHANGED: import SkepticAgent
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.generator import GeneratorAgent
from .agents.skeptic import SkepticAgent  # ADDED


class AgentCoordinator:
    def __init__(self):
        self.vuln_retriever = get_vuln_retriever_from_json(
            json_path="known_vulnerabilities/contract_vulns.json",
            base_dataset_dir="known_vulnerabilities",
            index_name="fyp",
            top_k=3,
        )

        self.analyzer = AnalyzerAgent(self.vuln_retriever)
        self.skeptic = SkepticAgent()  # ADDED
        self.exploiter = ExploiterAgent()
        self.generator = GeneratorAgent()

    def analyze_contract(self, contract_info: Dict) -> Dict:
        """
        1) Analyzer => detect vulnerabilities (all).
        2) Pass all to Skeptic => re-rank or filter them.
        3) [Future step] For the highest confidence ones, pass to Exploiter => plan exploit,
           then pass plan to Generator => produce transactions.
        """
        # 1. Analyzer => all vulnerabilities
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"status": "no_vulnerability_found"}
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        # Print all the vulnerabilities
        for idx, vuln in enumerate(vulnerabilities, start=1):
            print(f"Vulnerability #{idx}: {vuln['vulnerability_type']}")
            print(f"Affected functions: {vuln.get('affected_functions', [])}")
            print(f"Code snippet: {vuln.get('code_snippet', '')[:200]}...")
            print()

        # 2. Skeptic => re-check each vulnerability's validity
        #    The skeptic sorts them by .skeptic_confidence
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"], vulnerabilities
        )

        # 3. Now optionally pick each high-confidence vulnerability
        #    and generate a PoC plan
        #    For example, we can loop over them:
        generated_pocs = []
        for vul in rechecked_vulns:

            if vul.get("skeptic_confidence", 0) > 0.5:
                print(f"Generating PoC for: {vul['vulnerability_type']}")

                # call exploiter => plan
                plan_data = self.exploiter.generate_exploit_plan(vul)
                print("Exploit plan:", plan_data.get("exploit_plan"))

                # then call generator => produce PoC transactions or code
                tx_sequence = self.generator.generate(plan_data)
                # store result
                generated_pocs.append(
                    {
                        "vulnerability": vul,
                        "exploit_plan": plan_data.get("exploit_plan"),
                        "tx_sequence": tx_sequence,
                    }
                )

        return {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
        }
