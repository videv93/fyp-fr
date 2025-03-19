# ==============================
# File: llm_agents/agent_coordinator.py
# ==============================
import os
from typing import Dict

# Import the new function
from rag.doc_db import get_vuln_retriever_from_json

# CHANGED: import SkepticAgent
from .agents.analyzer import AnalyzerAgent
from .agents.exploiter import ExploiterAgent
from .agents.generator import GeneratorAgent
from .agents.skeptic import SkepticAgent
from .agents.runner import ExploitRunner
from .config import ModelConfig

from utils.print_utils import print_step, print_success, print_warning

class AgentCoordinator:
    def __init__(self, model_config=None, use_rag=True):
        """
        Initialize the agent coordinator with configurable models.

        Args:
            model_config: Optional ModelConfig instance. If None, default config will be used.
            use_rag: Boolean to enable/disable Retrieval Augmented Generation for analysis.
        """
        self.model_config = model_config or ModelConfig()
        self.use_rag = use_rag

        # Initialize retriever only if RAG is enabled
        if self.use_rag:
            self.vuln_retriever = get_vuln_retriever_from_json(
                json_path="known_vulnerabilities/contract_vulns.json",
                base_dataset_dir="known_vulnerabilities",
                index_name="fyp",
                top_k=3,
            )
        else:
            self.vuln_retriever = None

        self.analyzer = AnalyzerAgent(self.vuln_retriever, model_config=self.model_config)
        self.skeptic = SkepticAgent(model_config=self.model_config)
        self.exploiter = ExploiterAgent(model_config=self.model_config)
        self.generator = GeneratorAgent(model_config=self.model_config)
        self.runner = ExploitRunner(model_config=self.model_config)

    def analyze_contract(self, contract_info: Dict, auto_run_config: Dict = None) -> Dict:
        from rich.console import Console
        console = Console()

        # Set default auto-run config if none provided
        if auto_run_config is None:
            auto_run_config = {"auto_run": True, "max_retries": 3}

        # Configure runner's max retries
        self.runner.max_retries = auto_run_config.get("max_retries", 3)

        # 1. Analyzer => all vulnerabilities
        console.print("[bold blue]🔍 AnalyzerAgent: Starting initial vulnerability detection...[/bold blue]")
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])
        if not vulnerabilities:
            console.print("[bold yellow]AnalyzerAgent: No vulnerabilities found[/bold yellow]")
            return {"status": "no_vulnerability_found"}

        console.print(f"[bold green]✓ AnalyzerAgent: Found {len(vulnerabilities)} potential vulnerabilities[/bold green]")
        for i, v in enumerate(vulnerabilities):
            console.print(f"  - {v.get('vulnerability_type')} (confidence: {v.get('confidence_score', 0):.2f})")

        # 2. Skeptic => re-check validity
        console.print("\n[bold blue]🧐 SkepticAgent: Re-checking vulnerability validity...[/bold blue]")
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"], vulnerabilities
        )

        console.print("[bold green]✓ SkepticAgent: Completed verification[/bold green]")
        for i, v in enumerate(rechecked_vulns):
            old_score = v.get('confidence_score', 0)
            new_score = v.get('skeptic_confidence', 0)
            change = "↑" if new_score > old_score else "↓" if new_score < old_score else "→"
            console.print(f"  - {v.get('vulnerability_type')}: {old_score:.2f} {change} {new_score:.2f}")

        # 3. Generate PoCs for high-confidence vulnerabilities
        generated_pocs = []
        high_conf_vulns = [v for v in rechecked_vulns if v.get("skeptic_confidence", 0) > 0.5]

        # Generate for only one for now
        if high_conf_vulns:
            console.print(f"\n[bold blue]💡 ExploiterAgent: Generating educational demonstrations for {len(high_conf_vulns)} vulnerabilities...[/bold blue]")

            for i, vul in enumerate(high_conf_vulns):
                console.print(f"  Working on {vul.get('vulnerability_type')} (#{i+1}/{len(high_conf_vulns)})...")
                plan_data = self.exploiter.generate_exploit_plan(vul)

                console.print(f"\n[bold blue]🔧 GeneratorAgent: Creating PoC for {vul.get('vulnerability_type')}...[/bold blue]")

                # First generate the BaseTestWithBalanceLog.sol file if it doesn't exist
                if not os.path.exists("exploit/src/test/basetest.sol"):
                    base_file = self.generator.generate_basetest_file()
                    console.print(f"[dim]Created base file: {base_file}[/dim]")

                # Generate the PoC for this vulnerability
                poc_data = self.generator.generate(plan_data)

                # Run and fix the exploit if auto-run is enabled
                if auto_run_config.get("auto_run", True):
                    console.print(f"\n[bold blue]🔍 ExploitRunner: Testing and fixing PoC...[/bold blue]")
                    run_result = self.runner.run_and_fix_exploit(poc_data)

                    if run_result.get("success"):
                        console.print(f"[bold green]✓ Test executed successfully![/bold green]")
                    else:
                        if run_result.get("retries") > 0:
                            console.print(f"[bold yellow]⚠ Test failed after {run_result.get('retries')} fix attempts[/bold yellow]")
                            console.print(f"[dim]Error: {run_result.get('error', 'Unknown error')}[/dim]")
                        else:
                            console.print(f"[bold red]✗ Test failed and could not be fixed[/bold red]")
                            console.print(f"[dim]Error: {run_result.get('error', 'Unknown error')}[/dim]")

                    # Add execution results to the PoC data
                    poc_data["execution_results"] = {
                        "success": run_result.get("success", False),
                        "retries": run_result.get("retries", 0),
                        "error": run_result.get("error", ""),
                        "output": run_result.get("output", "")[:500]  # Truncate long outputs
                    }
                else:
                    console.print(f"[dim]Auto-run disabled. Test generated but not executed.[/dim]")

                generated_pocs.append({
                    "vulnerability": vul,
                    "exploit_plan": plan_data.get("exploit_plan"),
                    "poc_data": poc_data,
                })
                console.print(f"[bold green]✓ Generated demonstration for {vul.get('vulnerability_type')}[/bold green]")

        console.print("\n[bold green]✓ Agent workflow completed[/bold green]")
        return {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
        }
