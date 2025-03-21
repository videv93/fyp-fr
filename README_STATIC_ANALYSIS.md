# Static Analysis Sub-Component

This document explains the Static Analysis part of the project. The static analysis component is responsible for parsing and analyzing Solidity smart contracts to identify potential vulnerabilities and to generate detailed analysis reports.

## Overview

- **Purpose**: To perform a deep analysis of a given Solidity contract using static analysis techniques and established tools like Slither.
- **Key Features**:
  - Parses Solidity code to extract function details and constructs call graphs.
  - Detects potential vulnerability patterns using predefined detectors (e.g. reentrancy, access control issues).
  - Generates a comprehensive report on the findings to be used by subsequent components (e.g. LLM Agents).

## Workflow

1. **Input**: A Solidity contract file (.sol) is provided to the system.
2. **Parsing**: The `parse_contract.py` script processes the contract to extract necessary metadata and structure.
3. **Slither Analysis**: The contract is then passed to Slither detectors to identify typical vulnerabilities and build a call graph.
4. **Output**: A static analysis report is compiled summarizing all the detected issues and structural properties.

## Mermaid Diagram

```mermaid
flowchart TD
    A[Smart Contract (.sol)] --> B[parse_contract.py]
    B --> C[Slither Detectors]
    C --> D[Call Graph Generator]
    D --> E[Static Analysis Report]
```

## How to Run

1. Ensure that Slither is installed and properly configured.
2. Place the Solidity contract in the designated input directory.
3. Run the static analysis script (e.g., `python static_analysis/parse_contract.py`) to generate the report.

## Additional Notes

- The output report is used by other components such as the LLM Agents for further vulnerability validation and exploit planning.
- Error handling and logging are implemented to ensure traceability of the analysis process.
