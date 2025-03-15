# ==============================
# File: main.py
# ==============================
import os
import json
from dotenv import load_dotenv
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from utils.print_utils import *

def main():
    print_header("Smart Contract Vulnerability Analyzer")

    # Check environment
    try:
        load_dotenv()
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY not found")
        print_success("Environment loaded successfully")
    except Exception as e:
        print_error(f"Environment setup failed: {str(e)}")
        return

    # Load and analyze contract
    filepath = "static_analysis/test_contracts/sample2.sol"
    print_step(f"Analyzing contract: {filepath}")

    # Static Analysis
    with create_progress_spinner("Running static analysis") as progress:
        task = progress.add_task("Analyzing contract structure...")
        function_details, call_graph, detector_results = analyze_contract(filepath)
        progress.update(task, completed=True)

    print_success(f"Found {len(function_details)} functions to analyze")

    # Save detector results
    with open("static_analysis/test_contracts/contract_vulns.json", "w") as f:
        json.dump(detector_results, f, indent=4)

    # Read contract source
    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()

    # Prepare for LLM analysis
    contract_info = {
        "function_details": function_details,
        "call_graph": call_graph,
        "source_code": source_code,
        "detector_results": detector_results,
    }

    # Run LLM analysis
    print_header("Running LLM Analysis")
    coordinator = AgentCoordinator()
    results = coordinator.analyze_contract(contract_info)

    # Print results
    print_header("Analysis Results")
    rechecked = results.get("rechecked_vulnerabilities", [])

    if not rechecked:
        print_warning("No vulnerabilities found")
    else:
        print_success(f"Found {len(rechecked)} potential vulnerabilities")

        for idx, v in enumerate(rechecked, start=1):
            confidence = v.get('skeptic_confidence', 0)
            color = "red" if confidence > 0.7 else "yellow" if confidence > 0.4 else "green"

            console.print(f"\n[bold {color}]Vulnerability #{idx}: {v['vulnerability_type']}[/bold {color}]")
            console.print(f"Confidence: {confidence:.2f}")
            console.print(f"Reasoning: {v.get('reasoning','N/A')}")
            console.print(f"Validity: {v.get('validity_reasoning','')}")
            console.print("Code snippet:")
            console.print(v.get('code_snippet','')[:200] + "...", style="dim")
            console.print(f"Affected Functions: {', '.join(v.get('affected_functions', []))}")

    # Show PoCs
    print_header("Generated Proof of Concepts")
    pocs = results.get("generated_pocs", [])

    if not pocs:
        print_warning("No PoCs were generated")
    else:
        print_success(f"Generated {len(pocs)} PoCs for high-confidence vulnerabilities")

        for pidx, poc in enumerate(pocs, start=1):
            vuln = poc['vulnerability']
            console.print(f"\n[bold]PoC #{pidx}[/bold] - {vuln['vulnerability_type']}")
            console.print(f"Confidence: {vuln.get('skeptic_confidence', 0):.2f}")
            console.print("\nExploit Plan:")

            # Get all step types from the exploit plan
            setup_steps = poc["exploit_plan"].get("setup_steps", [])
            execution_steps = poc["exploit_plan"].get("execution_steps", [])
            validation_steps = poc["exploit_plan"].get("validation_steps", [])

            if setup_steps:
                console.print("[bold]Setup:[/bold]")
                for step in setup_steps:
                    console.print(f"• {step}")

            if execution_steps:
                console.print("[bold]Execution:[/bold]")
                for step in execution_steps:
                    console.print(f"• {step}")

            if validation_steps:
                console.print("[bold]Validation:[/bold]")
                for step in validation_steps:
                    console.print(f"• {step}")

            # If no steps found with the proper structure
            if not (setup_steps or execution_steps or validation_steps):
                console.print("[italic]No detailed steps available[/italic]")
                
            # Display PoC information
            if "poc_data" in poc:
                poc_data = poc["poc_data"]
                console.print("\n[bold]Generated Proof of Concept:[/bold]")
                console.print(f"File: [green]{poc_data.get('exploit_file', 'N/A')}[/green]")
                console.print(f"Execution: [blue]{poc_data.get('execution_command', 'N/A')}[/blue]")
                console.print("[dim]Use the file with Foundry to run the test and verify the vulnerability[/dim]")

if __name__ == "__main__":
    main()
