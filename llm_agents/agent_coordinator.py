# llm_agents/agent_coordinator.py

from typing import Dict, List
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.generator import GeneratorAgent
from rag.vectorstore import VulnerabilityKB

class AgentCoordinator:
    def __init__(self, kb: VulnerabilityKB):
        self.kb = kb
        self.analyzer = AnalyzerAgent(kb)
        self.exploiter = ExploiterAgent(kb)
        self.generator = GeneratorAgent(kb)

    def analyze_contract(self, contract_info: Dict) -> Dict:
        """
        Coordinates the analysis and exploit generation process for the entire contract.

        Args:
            contract_info (Dict): Contains 'function_details' and 'call_graph' of the contract.

        Returns:
            Dict: Contains vulnerabilities, exploit plans, and transaction sequences.
        """
        # 1. Analyzer determines vulnerabilities
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])

        if not vulnerabilities:
            return {"status": "no_vulnerability_found"}

        # 2. Exploiter plans exploit strategies for each vulnerability
        exploit_plans = []
        transactions = []

        for vuln in vulnerabilities:
            exploit_plan = self.exploiter.generate_exploit_plan(vuln)
            exploit_plans.append({
                "vulnerability_type": vuln.get("vulnerability_type"),
                "exploit_plan": exploit_plan.get("exploit_plan", {})
            })

            # 3. Generator creates transaction sequence based on the exploit plan
            tx_sequence = self.generator.generate(exploit_plan)
            transactions.append({
                "vulnerability_type": vuln.get("vulnerability_type"),
                "transactions": tx_sequence
            })

        return {
            "vulnerabilities": vulnerabilities,
            "exploit_plans": exploit_plans,
            "transactions": transactions
        }
