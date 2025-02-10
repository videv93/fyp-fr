# ==============================
# File: main.py
# ==============================
import os
import json
from dotenv import load_dotenv
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from pprint import pprint  # For pretty-printing


def main():
    load_dotenv()
    if not os.getenv("OPENAI_API_KEY"):
        raise ValueError("Please set OPENAI_API_KEY environment variable")

    # Path to the user's new contract that we want to analyze
    filepath = "static_analysis/test_contracts/sample.sol"
    function_details, call_graph, detector_results = analyze_contract(filepath)

    # Save the detector results in a JSON, with good formatting
    with open("static_analysis/test_contracts/contract_vulns.json", "w") as f:
        json.dump(detector_results, f, indent=4)

    # Read the contract's source code
    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()

    # Build a contract_info dict that includes the detector results
    contract_info = {
        "function_details": function_details,
        "call_graph": call_graph,
        "source_code": source_code,
        "detector_results": detector_results,
    }

    # Use the AgentCoordinator (which loads the Pinecone store from contract_vulns.json)
    coordinator = AgentCoordinator()
    results = coordinator.analyze_contract(contract_info)

    # Print results (existing workflow)
    print("=== ANALYSIS RESULTS ===")
    if results.get("vulnerabilities"):
        for idx, vuln in enumerate(results["vulnerabilities"], start=1):
            print(f"\nVulnerability {idx}:")
            print(f"  Type: {vuln.get('vulnerability_type', 'N/A')}")
            print(f"  Confidence Score: {vuln.get('confidence_score', 'N/A')}")
            print(f"  Reasoning: {vuln.get('reasoning', 'N/A')}")
            print(
                f"  Affected Functions: {', '.join(vuln.get('affected_functions', []) or [])}"
            )
    else:
        print("No vulnerabilities found or no results returned.")

    # Print targeted vulnerability, exploit plan, etc.
    target_vuln = results.get("target_vuln")
    if target_vuln:
        print("\n=== TARGETED VULNERABILITY ===")
        print(
            f"Type: {target_vuln.get('vulnerability_type')}, Score: {target_vuln.get('confidence_score')}"
        )
        print(f"Reasoning: {target_vuln.get('reasoning')}")
        print(f"Affected: {target_vuln.get('affected_functions')}")
    else:
        print("No targeted vulnerability was found.")

    print("\n=== EXPLOIT PLAN ===")
    exploit_plan = results.get("exploit_plan")
    if exploit_plan:
        print(exploit_plan)
    else:
        print("No exploit plan generated.")

    print("\n=== TRANSACTION SEQUENCE ===")
    tx_sequence = results.get("tx_sequence")
    if tx_sequence:
        print(tx_sequence)
    else:
        print("No transaction sequence generated.")


if __name__ == "__main__":
    main()
