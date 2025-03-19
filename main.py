# ==============================
# File: main.py
# ==============================
import os
import json
import argparse
from dotenv import load_dotenv
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.config import ModelConfig
from utils.print_utils import *

def parse_arguments():
    """Parse command line arguments for model configuration"""
    parser = argparse.ArgumentParser(description="Smart Contract Vulnerability Analyzer")

    # Add model configuration arguments
    parser.add_argument("--analyzer-model", default="o3-mini", help="Model for analyzer agent")
    parser.add_argument("--skeptic-model", default="o3-mini", help="Model for skeptic agent")
    parser.add_argument("--exploiter-model", default="o3-mini", help="Model for exploiter agent")
    parser.add_argument("--generator-model", default="o3-mini", help="Model for generator agent")
    parser.add_argument("--all-models", help="Use this model for all agents")
    parser.add_argument("--api-base", help="Base URL for OpenAI API")

    # Add contract file option
    parser.add_argument("--contract", default="static_analysis/test_contracts/sample3.sol",
                      help="Path to contract file to analyze")

    # Add auto-run options
    parser.add_argument("--no-auto-run", action="store_true",
                      help="Disable automatic execution of generated PoCs")
    parser.add_argument("--max-retries", type=int, default=3,
                      help="Maximum number of fix attempts for failed tests (default: 3)")
    
    # Add RAG option
    parser.add_argument("--no-rag", action="store_true",
                      help="Disable Retrieval Augmented Generation for analysis")

    return parser.parse_args()

def main():
    print_header("Smart Contract Vulnerability Analyzer")

    # Parse command line arguments
    args = parse_arguments()

    # Check environment
    try:
        load_dotenv()
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY not found")
        print_success("Environment loaded successfully")
    except Exception as e:
        print_error(f"Environment setup failed: {str(e)}")
        return

    # Setup model configuration
    if args.all_models:
        # Use the same model for all agents if --all-models is specified
        model_config = ModelConfig(
            analyzer_model=args.all_models,
            skeptic_model=args.all_models,
            exploiter_model=args.all_models,
            generator_model=args.all_models,
            base_url=args.api_base
        )
    else:
        # Use individual model specifications
        model_config = ModelConfig(
            analyzer_model=args.analyzer_model,
            skeptic_model=args.skeptic_model,
            exploiter_model=args.exploiter_model,
            generator_model=args.generator_model,
            base_url=args.api_base
        )

    # Display model configuration
    print_step("Model Configuration:")
    console.print(f"  Analyzer: [bold]{model_config.analyzer_model}[/bold]")
    console.print(f"  Skeptic: [bold]{model_config.skeptic_model}[/bold]")
    console.print(f"  Exploiter: [bold]{model_config.exploiter_model}[/bold]")
    console.print(f"  Generator: [bold]{model_config.generator_model}[/bold]")
    if args.api_base:
        console.print(f"  API Base URL: [dim]{args.api_base}[/dim]")

    # Load and analyze contract
    filepath = args.contract
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
    coordinator = AgentCoordinator(model_config=model_config, use_rag=not args.no_rag)

    # Pass auto-run configuration
    auto_run_config = {
        "auto_run": not args.no_auto_run,
        "max_retries": args.max_retries
    }

    # Display auto-run settings
    if not args.no_auto_run:
        print_step(f"Auto-run enabled with max {args.max_retries} fix attempts")
    else:
        print_step("Auto-run disabled, PoCs will be generated but not executed")
        
    # Display RAG settings
    if not args.no_rag:
        print_step("RAG enabled for enhanced vulnerability detection")
    else:
        print_step("RAG disabled, analysis will use only current contract code")

    results = coordinator.analyze_contract(contract_info, auto_run_config=auto_run_config)

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

                # Show execution results if available
                if "execution_results" in poc_data:
                    results = poc_data["execution_results"]
                    if results.get("success"):
                        console.print(f"Execution: [bold green]SUCCESS[/bold green] ✓")
                    else:
                        if results.get("retries", 0) > 0:
                            console.print(f"Execution: [bold yellow]FAILED[/bold yellow] after {results.get('retries')} fix attempts ⚠")
                        else:
                            console.print(f"Execution: [bold red]FAILED[/bold red] ✗")

                        # Show error details if we have them
                        if results.get("error"):
                            console.print(f"[dim]Error: {results.get('error')[:200]}...[/dim]")
                else:
                    # Fallback if no execution results
                    console.print(f"Execution Command: [blue]{poc_data.get('execution_command', 'N/A')}[/blue]")
                    console.print("[dim]The test was generated but not automatically executed[/dim]")

if __name__ == "__main__":
    main()
