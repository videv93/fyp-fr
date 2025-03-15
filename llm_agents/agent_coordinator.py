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

from utils.print_utils import print_step

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
        # 1. Analyzer => all vulnerabilities
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"status": "no_vulnerability_found"}

        print_step(f"Found {len(vulnerabilities)} potential vulnerabilities")

        # 2. Skeptic => re-check validity
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"], vulnerabilities
        )

        # 3. Generate PoCs for high-confidence vulnerabilities
        generated_pocs = []
        high_conf_vulns = [v for v in rechecked_vulns if v.get("skeptic_confidence", 0) > 0.5]

        if high_conf_vulns:
            print_step(f"Generating PoCs for {len(high_conf_vulns)} high-confidence vulnerabilities")

            for vul in high_conf_vulns:
                plan_data = self.exploiter.generate_exploit_plan(vul)
                tx_sequence = self.generator.generate(plan_data)
                generated_pocs.append({
                    "vulnerability": vul,
                    "exploit_plan": plan_data.get("exploit_plan"),
                    "tx_sequence": tx_sequence,
                })

        return {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
        }
