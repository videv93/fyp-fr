# ==============================
# File: llm_agents/agent_coordinator.py
# ==============================
from typing import Dict
# Import the new function
from rag.doc_db import get_vuln_retriever_from_json

from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.generator import GeneratorAgent

class AgentCoordinator:
    def __init__(self):
        # Build a retriever from the JSON-based dataset
        # Suppose your dataset is "dataset/" and your JSON is "contract_vulns.json" in that directory.
        self.vuln_retriever = get_vuln_retriever_from_json(
            json_path="known_vulnerabilities/contract_vulns.json",
            base_dataset_dir="known_vulnerabilities",
            index_name="fyp",
            top_k=3
        )

        self.analyzer = AnalyzerAgent(self.vuln_retriever)
        self.exploiter = ExploiterAgent()
        self.generator = GeneratorAgent()

    def analyze_contract(self, contract_info: Dict) -> Dict:
        """
        Coordinates the analysis & exploit generation process for the entire contract.
        """
        # 1. Analyzer => detect vulnerabilities
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])

        if not vulnerabilities:
            return {"status": "no_vulnerability_found"}

        # 2. Sort vulnerabilities by confidence
        vulnerabilities_sorted = sorted(vulnerabilities, key=lambda x: x.get("confidence_score", 0), reverse=True)
        target_vuln = vulnerabilities_sorted[0]

        # 3. Exploiter => plan exploit
        exploit_plan = self.exploiter.generate_exploit_plan(target_vuln)

        # 4. Generator => produce transaction(s)
        tx_sequence = self.generator.generate(exploit_plan)

        return {
            "vulnerabilities": vulnerabilities_sorted,
            "target_vuln": target_vuln,
            "exploit_plan": exploit_plan.get("exploit_plan"),
            "tx_sequence": tx_sequence
        }
