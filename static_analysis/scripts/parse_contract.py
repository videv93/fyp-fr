from slither import Slither
from slither.core.declarations.function import Function
from slither.core.declarations.contract import Contract
from slither.printers.abstract_printer import AbstractPrinter
from slither.printers.call.call_graph import PrinterCallGraph
from all_detectors import DETECTORS
from typing import Dict, List

def analyze_contract(filepath: str):
    """
    Analyzes a Solidity contract using Slither and returns:
    1. A list of function details (name, visibility, parameters, returns, etc.)
    2. A call graph mapping each function to the functions it calls
    """

    # Initialize Slither on the given file. This parses and compiles the contract.
    slither = Slither(filepath)
    printer = PrinterCallGraph(slither, None)
    # for detector_class in all_detectors.DETECTORS:
    for detector_class in DETECTORS:
        slither.register_detector(detector_class)
    detectors_results = slither.run_detectors()
    cfg_data = printer.get_call_graph_content()
    all_function_details = []
    call_graph = cfg_data

    # Iterate over each contract in the source
    for contract in slither.contracts:
        contract_name = contract.name

        # Iterate over each function in the contract
        for func in contract.functions:
            # Extract basic function info
            func_name = func.name
            visibility = str(func.visibility)  # e.g. 'public', 'external', ...
            parameters = [(str(p.type), p.name) for p in func.parameters]
            returns = [(str(r.type), r.name) for r in func.returns]

            # Lines of code (start_line, end_line). Not all functions have source mappings, handle None carefully.
            # source_mapping is typically a Slither object with multiple fields.
            start_line = func.source_mapping.start if func.source_mapping else None
            end_line = func.source_mapping.end if func.source_mapping else None

            # Prepare the function detail dict
            func_detail = {
                "contract": contract_name,
                "function": func_name,
                "visibility": visibility,
                "parameters": parameters,
                "returns": returns,
                "start_line": start_line,
                "end_line": end_line
            }
            all_function_details.append(func_detail)


    return all_function_details, call_graph, detectors_results

if __name__ == "__main__":
    # Example usage:
    filepath = "/Users/advait/Desktop/NTU/fyp-fr/static_analysis/test_contracts/reentrancy.sol"  # Adjust path to your .sol file
    function_details, cg, detector_results = analyze_contract(filepath)

    # Print function details
    print("==== Function Details ====")
    for f in function_details:
        print(f"Contract: {f['contract']}")
        print(f"Function: {f['function']}")
        print(f"Visibility: {f['visibility']}")
        print(f"Parameters: {f['parameters']}")
        print(f"Returns: {f['returns']}")
        print(f"Lines: {f['start_line']} - {f['end_line']}")
        print()

    # Print call graph
    # Returns the Call Graph formatted for DOT files
    print("==== Call Graph ====")
    print(cg['all_contracts'])

    # Print slither detector results
    # NOTE: This is not really necessary for our purposes, but included for completeness
    print("==== Detector Results ====")
    print(detector_results)
