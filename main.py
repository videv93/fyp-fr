# main.py

import os
from llm_agents.agents import exploiter
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from rag.vectorstore import VulnerabilityKB

def main():
    # Ensure OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        raise ValueError("Please set OPENAI_API_KEY environment variable")

    # 1. Initialize knowledge base
    kb = VulnerabilityKB()

    # 2. Analyze contract
    filepath = "static_analysis/test_contracts/sample.sol"
    function_details, call_graph, detector_results = analyze_contract(filepath)

    contract_info = {
        "function_details": function_details,
        "call_graph": call_graph
    }

    # Print the Stage
    print("==== STATIC ANALYSIS ====")
    print("Contract Call Graph:")
    print(call_graph['all_contracts'])
    print("\nFunction Details:")

    # Loop through the list and print each function detail
    for f in function_details:
        print(f"\nContract: {f['contract']}")
        print(f"Function: {f['function']}")
        print(f"Visibility: {f['visibility']}")
        print(f"Parameters: {f['parameters']}")
        print(f"Returns: {f['returns']}")
        print(f"Lines: {f['start_line']} - {f['end_line']}\n")

    # 3. Initialize coordinator with knowledge base
    coordinator = AgentCoordinator(kb)

    # 4. Get results
    results = coordinator.analyze_contract(contract_info)

    # Print Analysis Results
    print("==== ANALYSIS RESULTS ====")
    if results.get("vulnerabilities"):
        for idx, vuln in enumerate(results["vulnerabilities"], start=1):
            print(f"\nVulnerability {idx}:")
            print(f"  Type: {vuln.get('vulnerability_type', 'N/A')}")
            print(f"  Confidence Score: {vuln.get('confidence_score', 'N/A')}")
            print(f"  Reasoning: {vuln.get('reasoning', 'N/A')}")
            print(f"  Affected Functions: {', '.join(vuln.get('affected_functions', []))}")
    else:
        print("No vulnerabilities found.")

    # Print Targeted Vulnerability
    print("\n==== TARGETED VULNERABILITY ====")
    target_vuln = results.get("target_vuln")
    if target_vuln:
        print(f"\nTargeted Vulnerability:")
        print(f"  Type: {target_vuln.get('vulnerability_type', 'N/A')}")
        print(f"  Confidence Score: {target_vuln.get('confidence_score', 'N/A')}")
        print(f"  Reasoning: {target_vuln.get('reasoning', 'N/A')}")
        print(f"  Affected Functions: {', '.join(target_vuln.get('affected_functions', []))}")
    else:
        print("No targeted vulnerability found.")

    # Print Exploit Plan
    print("\n==== EXPLOIT PLAN ====")
    exploit_plan = results.get("exploit_plan")

    if exploit_plan:
        print(f"\nExploit Plan:")
        print(f"  Setup Steps:")
        for step in exploit_plan.get("setup_steps", []):
            print(f"    - {step}")
        print(f"  Execution Steps:")
        for step in exploit_plan.get("execution_steps", []):
            print(f"    - {step}")
        print(f"  Validation Steps:")
        for step in exploit_plan.get("validation_steps", []):
            print(f"    - {step}")
    else:
        print("No exploit plan generated.")

    # print("\n==== EXPLOIT PLANS ====")
    # if results.get("exploit_plans"):
    #     for idx, exploit in enumerate(results["exploit_plans"], start=1):
    #         print(f"\nExploit Plan for Vulnerability {idx} ({exploit['vulnerability_type']}):")
    #         print(f"  Setup Steps:")
    #         for step in exploit['exploit_plan'].get("setup_steps", []):
    #             print(f"    - {step}")
    #         print(f"  Execution Steps:")
    #         for step in exploit['exploit_plan'].get("execution_steps", []):
    #             print(f"    - {step}")
    #         print(f"  Validation Steps:")
    #         for step in exploit['exploit_plan'].get("validation_steps", []):
    #             print(f"    - {step}")
    # else:
    #     print("No exploit plans generated.")

    # Print Transaction Sequence
    print("\n==== TRANSACTION SEQUENCE ====")
    tx_sequence = results.get("tx_sequence")
    if tx_sequence:
        print(f"\nTransaction Sequence:")
        for tx in tx_sequence:
            print(f"  From: {tx.get('from', 'N/A')}")
            print(f"  To: {tx.get('to', 'N/A')}")
            print(f"  Value: {tx.get('value', 'N/A')}")
            print(f"  Data: {tx.get('data', 'N/A')}")
    else:
        print("No transaction sequence generated.")

    # print("\n==== EXPLOIT TRANSACTIONS ====")
    # if results.get("transactions"):
    #     for idx, tx in enumerate(results["transactions"], start=1):
    #         print(f"\nTransaction Sequence for Vulnerability {idx} ({tx['vulnerability_type']}):")
    #         for tx_detail in tx['transactions']:
    #             print(f"  - From: {tx_detail.get('from', 'N/A')}")
    #             print(f"    To: {tx_detail.get('to', 'N/A')}")
    #             print(f"    Value: {tx_detail.get('value', 'N/A')}")
    #             print(f"    Data: {tx_detail.get('data', 'N/A')}")
    # else:
    #     print("No transaction sequences generated.")

if __name__ == "__main__":
    main()
