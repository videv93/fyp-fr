import requests
import json
import re
from collections import defaultdict
import os
from dotenv import load_dotenv

load_dotenv()

BSCSCAN_API_KEY = os.getenv("BSCSCAN_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")


def fetch_and_flatten_contract(
    network: str,
    contract_address: str,
    api_key: str,
    output_file: str = "contract_flat.sol",
):
    explorers = {
        "ethereum": "https://api.etherscan.io/api",
        "bsc": "https://api.bscscan.com/api",
        "polygon": "https://api.polygonscan.com/api",
    }

    if network not in explorers:
        raise ValueError("Unsupported network. Use: ethereum, bsc, polygon.")

    url = f"{explorers[network]}?module=contract&action=getsourcecode&address={contract_address}&apikey={api_key}"
    response = requests.get(url).json()

    if response["status"] != "1" or not response["result"]:
        raise Exception(
            "Failed to fetch contract source. Check contract address or API key."
        )

    contract_data = response["result"][0]
    source_code = contract_data["SourceCode"].strip()

    if source_code.startswith("{{"):
        try:
            parsed_code = json.loads(source_code[1:-1])  # Remove surrounding braces
            sources = parsed_code.get("sources", {})

            contract_parts = {file: data["content"] for file, data in sources.items()}

            print(f"Found {len(contract_parts)} contract parts.")
            print("Flattening...")

            sorted_contracts = order_contracts_by_references(contract_parts)

            combined_code = "\n\n".join(sorted_contracts)
            source_code = process_source_code(combined_code)
        except json.JSONDecodeError:
            raise Exception("Error parsing multi-file contract source.")
    else:
        source_code = process_source_code(source_code)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(source_code)

    print(f"Flattened contract saved to {output_file}")


def order_contracts_by_references(contract_parts):
    from collections import defaultdict
    import re

    # Update the regex to also capture interfaces and libraries
    pattern = re.compile(
        r"(?:contract|interface|library)\s+(\w+)\s*(?:is\s+([^{]+))?\s*\{", re.MULTILINE
    )

    contract_to_file = {}
    file_dependencies = defaultdict(set)

    # First pass: map each identifier to its file
    for filename, content in contract_parts.items():
        for match in pattern.finditer(content):
            identifier = match.group(1)
            contract_to_file[identifier] = filename

    # Second pass: record file dependencies based on inheritance/implementation
    for filename, content in contract_parts.items():
        for match in pattern.finditer(content):
            identifier = match.group(1)
            parents = match.group(2)
            if parents:
                for parent in re.split(r"\s*,\s*", parents.strip()):
                    parent_file = contract_to_file.get(parent)
                    if parent_file and parent_file != filename:
                        file_dependencies[filename].add(parent_file)

    visited = set()
    ordered_sources = []

    def visit(file_node):
        if file_node in visited:
            return
        visited.add(file_node)
        for dep in file_dependencies.get(file_node, []):
            visit(dep)
        ordered_sources.append(contract_parts[file_node])

    for filename in contract_parts:
        if filename not in visited:
            visit(filename)

    return ordered_sources


def process_source_code(source_code: str) -> str:
    import re

    # Remove all import statements
    source_code = re.sub(r"^\s*import\s+.*$", "", source_code, flags=re.MULTILINE)

    # Capture and remove SPDX license declarations (if any)
    spdx_pattern = re.compile(r"^\s*//\s*SPDX-License-Identifier:.*$", re.MULTILINE)
    spdx_matches = spdx_pattern.findall(source_code)
    source_code = spdx_pattern.sub("", source_code)
    spdx_header = spdx_matches[0].strip() if spdx_matches else ""

    # Capture and remove all pragma solidity declarations
    pragma_pattern = re.compile(r"^\s*pragma solidity.*?;\s*$", re.MULTILINE)
    pragma_matches = pragma_pattern.findall(source_code)
    source_code = pragma_pattern.sub("", source_code)
    pragma_header = pragma_matches[0].strip() if pragma_matches else ""

    # Build the header with only one SPDX and one pragma (if found)
    header = ""
    if spdx_header:
        header += spdx_header + "\n"
    if pragma_header:
        header += pragma_header + "\n"

    # Return header + cleaned source code
    return header + "\n" + source_code.strip()


# Example usage
output_path = os.path.join(
    os.path.dirname(__file__), "..", "static_analysis", "test_contracts", "sample.sol"
)
fetch_and_flatten_contract(
    "bsc",
    "0x109ea28dbdea5e6ec126fbc8c33845dfe812a300",
    BSCSCAN_API_KEY,
    output_file=output_path,
)
