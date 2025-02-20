# ==============================
# File: main.py
# ==============================
import os
import json
from dotenv import load_dotenv
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator


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

    # Use the AgentCoordinator
    coordinator = AgentCoordinator()
    results = coordinator.analyze_contract(contract_info)

    print("=== SKEPTIC RE-CHECKED VULNERABILITIES ===")
    rechecked = results.get("rechecked_vulnerabilities", [])
    for idx, v in enumerate(rechecked, start=1):
        print(
            f"\nVuln #{idx}: {v['vulnerability_type']}  (SkepticConfidence={v.get('skeptic_confidence',0)})"
        )
        print(f"Reasoning: {v.get('reasoning','N/A')}")
        print(f"Validity: {v.get('validity_reasoning','')}")
        print(f"CODE SNIPPET:\n{v.get('code_snippet','')[:200]}...")  # truncated
        print("Affected Functions:", v.get("affected_functions", []))

    # Show any PoCs we generated
    pocs = results.get("generated_pocs", [])
    print("\n=== GENERATED PoCs FOR HIGH-CONFIDENCE VULNS ===")
    for pidx, poc in enumerate(pocs, start=1):
        print(
            f"\n[PoC {pidx}] Vulnerability: {poc['vulnerability']['vulnerability_type']}"
        )
        print(f"SkepticConfidence: {poc['vulnerability'].get('skeptic_confidence', 0)}")
        print("Exploit Plan:", poc["exploit_plan"])
        print("Tx Sequence:", poc["tx_sequence"])


if __name__ == "__main__":
    main()
