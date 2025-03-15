from slither import Slither
from slither.core.declarations.function import Function
from slither.core.declarations.contract import Contract
from slither.printers.abstract_printer import AbstractPrinter
from slither.solc_parsing.expressions.find_variable import SolidityFunction
from .slither_detectors import DETECTORS
from .call_graph_printer import PrinterCallGraphV2
from typing import Dict, List


def analyze_contract(filepath: str):
    """
    Analyzes a Solidity contract using Slither and returns:
    1. A list of function details (name, visibility, parameters, returns, etc.)
    2. A call graph mapping each function to the functions it calls
    """
    # Define the solc_remaps
    solc_remaps = [
        "@openzeppelin=/Users/advait/Desktop/NTU/fyp-fr/static_analysis/node_modules/@openzeppelin"
    ]
    # Initialize Slither on the given file. This parses and compiles the contract.
    slither = Slither(
        filepath,
        solc_args="--optimize",
        solc_remaps=solc_remaps,
    )

    # slither = Slither(filepath)
    printer = PrinterCallGraphV2(slither, None)

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
            # Exclude function if func_name == constructor
            if func_name == "slitherConstructorVariables":
                continue

            visibility = str(func.visibility)  # e.g. 'public', 'external', ...
            if visibility == "internal":
                continue
            parameters = [(str(p.type), p.name) for p in func.parameters]
            returns = [(str(r.type), r.name) for r in func.returns]

            # Lines of code (start_line, end_line). Not all functions have source mappings, handle None carefully.
            start_line = func.source_mapping.start if func.source_mapping else None
            end_line = func.source_mapping.end if func.source_mapping else None

            # Get functions being called
            called_functions = [
                call.name
                for call in func.internal_calls
                if not isinstance(call, SolidityFunction)
            ]

            # Prepare the function detail dict
            func_detail = {
                "contract": contract_name,
                "function": func_name,
                "visibility": visibility,
                "parameters": parameters,
                "returns": returns,
                "start_line": start_line,
                "end_line": end_line,
                "called_functions": called_functions,
                "content": func.source_mapping.content if func.source_mapping else None,
            }

            all_function_details.append(func_detail)

    return all_function_details, call_graph, detectors_results


if __name__ == "__main__":
    # Example usage:
    filepath = "/Users/advait/Desktop/NTU/fyp-fr/static_analysis/test_contracts/code.sol"  # Adjust path to your .sol file
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
    print(cg["all_contracts"])
