from slither import Slither
from slither.core.declarations.function import Function
from slither.core.declarations.contract import Contract
from slither.printers.abstract_printer import AbstractPrinter
from slither.solc_parsing.expressions.find_variable import SolidityFunction
from .slither_detectors import DETECTORS
from .call_graph_printer import PrinterCallGraphV2
from typing import Dict, List
import json
import os
from .extract_contracts import process_contract_file


def _detect_foundry_project(filepath: str) -> str:
    """
    Detects if the contract is part of a Foundry project by looking for foundry.toml.
    Returns the project root directory if found, None otherwise.
    """
    current_dir = os.path.dirname(os.path.abspath(filepath))

    # Walk up the directory tree looking for foundry.toml
    while current_dir != os.path.dirname(current_dir):  # Stop at root
        foundry_config = os.path.join(current_dir, 'foundry.toml')
        if os.path.exists(foundry_config):
            return current_dir
        current_dir = os.path.dirname(current_dir)

    return None


def analyze_contract(filepath: str):
    """
    Analyzes a Solidity contract using Slither and returns:
    1. A list of function details (name, visibility, parameters, returns, etc.)
    2. A call graph mapping each function to the functions it calls
    """
    # Check if this is a Foundry project
    foundry_root = _detect_foundry_project(filepath)

    # Preprocess the contract file - check if it's a JSON bundle and extract if needed
    temp_dir = None
    try:
        # Process the file, potentially extracting contracts if it's a JSON bundle
        processed_filepath, temp_dir = process_contract_file(filepath)
        if processed_filepath != filepath:
            print(f"Preprocessed JSON contract: {filepath} -> {processed_filepath}")
            filepath = processed_filepath
            # Re-check for Foundry project after processing
            if foundry_root is None:
                foundry_root = _detect_foundry_project(filepath)
    except Exception as e:
        print(f"Error preprocessing contract: {e}")
        # Continue with the original filepath

    # Initialize Slither - if Foundry project detected, use it directly
    if foundry_root:
        print(f"→ Detected Foundry project at: {foundry_root}")
        # Convert filepath to absolute path before changing directory
        abs_filepath = os.path.abspath(filepath)
        # Change to foundry project directory for Slither to pick up foundry.toml
        original_cwd = os.getcwd()
        os.chdir(foundry_root)
        try:
            slither = Slither(
                abs_filepath,
                foundry_compile_all=True,
                foundry_out_directory=os.path.join(foundry_root, "out")
            )
        finally:
            os.chdir(original_cwd)
    else:
        # Fallback to hardcoded remaps (legacy behavior)
        solc_remaps = [
            "@openzeppelin=/Users/advait/Desktop/NTU/fyp-fr/static_analysis/node_modules/@openzeppelin"
        ]
        slither = Slither(
            filepath,
            solc_args="--via-ir --optimize",
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

    # Clean up temp directory if we created one
    if temp_dir and os.path.exists(temp_dir):
        print(f"Note: Temporary extracted files are in {temp_dir}")
        # We're not removing the directory to allow for inspection
        # import shutil
        # shutil.rmtree(temp_dir)
        
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
