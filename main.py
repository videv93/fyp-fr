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
    
    # Add PoC generation and report export options
    parser.add_argument("--skip-poc", action="store_true",
                      help="Skip PoC generation and stop at exploit plans")
    parser.add_argument("--export-md", action="store_true",
                      help="Export analysis report as Markdown file")

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
            base_url=args.api_base,
            skip_poc_generation=args.skip_poc,
            export_markdown=args.export_md
        )
    else:
        # Use individual model specifications
        model_config = ModelConfig(
            analyzer_model=args.analyzer_model,
            skeptic_model=args.skeptic_model,
            exploiter_model=args.exploiter_model,
            generator_model=args.generator_model,
            base_url=args.api_base,
            skip_poc_generation=args.skip_poc,
            export_markdown=args.export_md
        )

    # Display model configuration
    print_step("Configuration:")
    console.print(f"  Analyzer: [bold]{model_config.analyzer_model}[/bold]")
    console.print(f"  Skeptic: [bold]{model_config.skeptic_model}[/bold]")
    console.print(f"  Exploiter: [bold]{model_config.exploiter_model}[/bold]")
    console.print(f"  Generator: [bold]{model_config.generator_model}[/bold]")
    if args.api_base:
        console.print(f"  API Base URL: [dim]{args.api_base}[/dim]")
    console.print(f"  Skip PoC Generation: [bold]{'Yes' if model_config.skip_poc_generation else 'No'}[/bold]")
    console.print(f"  Export Markdown Report: [bold]{'Yes' if model_config.export_markdown else 'No'}[/bold]")

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
    
    # Export results to markdown if configured
    if model_config.export_markdown:
        export_results_to_markdown(filepath, results)

def export_results_to_markdown(contract_path, results):
    """Export analysis results to a markdown file"""
    from datetime import datetime
    import os
    
    # Create output filename based on the contract name
    contract_name = os.path.basename(contract_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"analysis_report_{contract_name}_{timestamp}.md"
    
    print_step(f"Exporting analysis report to {output_file}")
    
    rechecked_vulns = results.get("rechecked_vulnerabilities", [])
    pocs = results.get("generated_pocs", [])
    
    with open(output_file, "w") as f:
        # Write header
        f.write(f"# Smart Contract Vulnerability Analysis Report\n\n")
        f.write(f"**Contract:** {contract_path}\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Vulnerability summary
        f.write(f"## Vulnerability Summary\n\n")
        if not rechecked_vulns:
            f.write("No vulnerabilities were detected in this contract.\n\n")
        else:
            f.write(f"Found {len(rechecked_vulns)} potential vulnerabilities:\n\n")
            
            # Create a summary table
            f.write("| # | Vulnerability Type | Confidence | Affected Functions |\n")
            f.write("|---|-------------------|------------|--------------------|\n")
            
            for idx, vuln in enumerate(rechecked_vulns, start=1):
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                confidence = float(vuln.get('skeptic_confidence', 0))
                affected = ', '.join(vuln.get('affected_functions', ['Unknown']))
                f.write(f"| {idx} | {vuln_type} | {confidence:.2f} | {affected} |\n")
            
            f.write("\n")
        
        # Detailed vulnerability analysis
        if rechecked_vulns:
            f.write("## Detailed Analysis\n\n")
            
            for idx, vuln in enumerate(rechecked_vulns, start=1):
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                confidence = float(vuln.get('skeptic_confidence', 0))
                
                f.write(f"### Vulnerability #{idx}: {vuln_type}\n\n")
                f.write(f"**Confidence:** {confidence:.2f}\n\n")
                
                if vuln.get('reasoning'):
                    f.write(f"**Reasoning:**\n\n{vuln.get('reasoning')}\n\n")
                
                if vuln.get('validity_reasoning'):
                    f.write(f"**Validation:**\n\n{vuln.get('validity_reasoning')}\n\n")
                
                if vuln.get('code_snippet'):
                    f.write(f"**Code Snippet:**\n\n```solidity\n{vuln.get('code_snippet')}\n```\n\n")
                
                if vuln.get('affected_functions'):
                    f.write(f"**Affected Functions:** {', '.join(vuln.get('affected_functions'))}\n\n")
                
                # Look for a corresponding PoC
                matching_poc = next((p for p in pocs if p["vulnerability"].get("vulnerability_type") == vuln_type), None)
                if matching_poc and matching_poc.get("exploit_plan"):
                    f.write("**Exploit Plan:**\n\n")
                    
                    # Add all steps from the exploit plan
                    plan = matching_poc["exploit_plan"]
                    
                    if plan.get("setup_steps"):
                        f.write("*Setup Steps:*\n\n")
                        for step in plan.get("setup_steps", []):
                            f.write(f"- {step}\n")
                        f.write("\n")
                    
                    if plan.get("execution_steps"):
                        f.write("*Execution Steps:*\n\n")
                        for step in plan.get("execution_steps", []):
                            f.write(f"- {step}\n")
                        f.write("\n")
                    
                    if plan.get("validation_steps"):
                        f.write("*Validation Steps:*\n\n")
                        for step in plan.get("validation_steps", []):
                            f.write(f"- {step}\n")
                        f.write("\n")
                
                # Add a separator between vulnerabilities
                f.write("---\n\n")
        
        # PoC information if any were generated
        if pocs:
            f.write("## Proof of Concept Exploits\n\n")
            
            for idx, poc in enumerate(pocs, start=1):
                vuln = poc['vulnerability']
                vuln_type = vuln.get('vulnerability_type', 'Unknown')
                
                f.write(f"### PoC #{idx}: {vuln_type}\n\n")
                
                # Add PoC file information if it exists
                if "poc_data" in poc:
                    poc_data = poc["poc_data"]
                    f.write(f"**File:** {poc_data.get('exploit_file', 'N/A')}\n\n")
                    
                    # Add execution results if available
                    if "execution_results" in poc_data:
                        results = poc_data["execution_results"]
                        if results.get("success"):
                            f.write("**Execution:** ✅ SUCCESS\n\n")
                        else:
                            f.write(f"**Execution:** ❌ FAILED after {results.get('retries', 0)} fix attempts\n\n")
                            
                            if results.get("error"):
                                f.write(f"**Error:** {results.get('error')}\n\n")
                    
                    # Add PoC code if available
                    if poc_data.get("exploit_code"):
                        f.write("**Exploit Code:**\n\n```solidity\n")
                        f.write(poc_data.get("exploit_code"))
                        f.write("\n```\n\n")
                
                # Add a separator between PoCs
                f.write("---\n\n")
        
        # Footer
        f.write("## Recommendations\n\n")
        f.write("For each identified vulnerability, consider implementing the following mitigations:\n\n")
        
        # Add generic recommendations based on found vulnerability types
        vuln_types = [v.get('vulnerability_type', '').lower() for v in rechecked_vulns]
        
        if any('reentrancy' in vt for vt in vuln_types):
            f.write("- **For Reentrancy**: Implement checks-effects-interactions pattern and consider using ReentrancyGuard.\n")
        
        if any('overflow' in vt or 'underflow' in vt or 'arithmetic' in vt for vt in vuln_types):
            f.write("- **For Arithmetic Issues**: Use SafeMath library or Solidity 0.8.x built-in overflow checking.\n")
        
        if any('access' in vt or 'authorization' in vt or 'permission' in vt for vt in vuln_types):
            f.write("- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.\n")
        
        if any('oracle' in vt or 'price' in vt for vt in vuln_types):
            f.write("- **For Oracle Manipulation**: Use time-weighted average prices and multiple independent oracle sources.\n")
        
        # Add a general recommendation
        f.write("- **For All Vulnerabilities**: Consider a professional audit before deploying to production.\n\n")
        
        f.write("*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*\n")
    
    print_success(f"Report exported to {output_file}")

if __name__ == "__main__":
    main()
