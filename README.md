# FYP: Generate Vulnerable Transaction Sequences for Smart Contract using Large Language Models

# AuditAgent: LLM-Powered Smart Contract Vulnerability Analysis & Exploit Generation

**AuditAgent** is an advanced system that leverages a multi-agent Large Language Model (LLM) workflow to automatically analyze smart contracts, identify potential vulnerabilities, and generate proof-of-concept (PoC) exploit code. It integrates static analysis, Retrieval-Augmented Generation (RAG), and a pipeline of specialized AI agents to provide deep security insights.

| Section                                         | Description                                                                     |
| :---------------------------------------------- | :------------------------------------------------------------------------------ |
| [Introduction](#auditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagentauditagent-llm-powered-smart-contract-vulnerability-analysis--exploit-generation) | Project overview and goals.                                                     |
| [Visual Showcase](#visual-showcase)             | See AuditAgent in action (GUI & CLI).                                           |
| [How It Works](#how-it-works)                   | High-level explanation of the analysis workflow.                                |
| [Core Features](#core-features)                 | Key capabilities of the system.                                                 |
| [Architecture Deep Dive](#architecture-deep-dive) | Detailed system architecture and agent roles.                                   |
| [Prerequisites](#prerequisites)                 | Software and keys needed before installation.                                   |
| [Installation & Setup](#installation--setup)    | Step-by-step guide to get the system running.                                   |
| [Running an Analysis](#running-an-analysis)     | How to use the CLI to analyze contracts.                                        |
| [Command-Line Flags Explained](#command-line-flags-explained) | Detailed breakdown of all available options.                          |
| [Understanding the Output](#understanding-the-output) | What files are created and how to interpret the results.                      |
| [Automatic PoC Execution & Fixing](#automatic-poc-execution--fixing) | Details on the automated exploit testing and self-correction feature.         |
| [Troubleshooting](#troubleshooting)             | Solutions for common setup and execution issues.                                |

---

## Visual Showcase

### Web GUI (Example Interface)

*Note: The core logic runs via CLI; a GUI might be built separately.*

![image](https://github.com/user-attachments/assets/eac050fa-2856-4f30-80f6-06192db41b4c)
*(Example: Contract input)*

![image](https://github.com/user-attachments/assets/2c254dff-7c6e-4dc9-b70d-206f3e778e51)
*(Example: Analysis results)*

![image](https://github.com/user-attachments/assets/e2656cd4-0fa3-4d70-a8cd-550850c5daba)
*(Example: Vulnerability details)*

![image](https://github.com/user-attachments/assets/48be7de8-8693-49b3-911e-4f032042b77c)
*(Example: Generated PoC)*

### Command-Line Interface (CLI) Output

AuditAgent provides rich, real-time feedback directly in your terminal:

https://github.com/user-attachments/assets/8360a8b6-4ca0-49d3-be3c-94c195b3c5a3

---

## How It Works

AuditAgent follows a sophisticated pipeline to analyze smart contracts:

1.  **Input:** You provide a Solidity smart contract file, a directory of contracts, or a contract address on a supported blockchain.
2.  **Static Analysis:** The system uses **Slither** to parse the contract(s), understand the code structure, identify function calls, and perform initial checks based on predefined patterns. If analyzing a multi-file project, it identifies inter-contract relationships.
3.  **LLM-Powered Analysis (Multi-Agent Pipeline):**
    *   **(Optional) Project Context:** If multiple contracts are involved, the `ProjectContextLLMAgent` analyzes interactions between them.
    *   **Vulnerability Identification (`AnalyzerAgent`):** This agent analyzes the code, leveraging static analysis results and (optionally) a **RAG** system (Pinecone Vector DB) containing known vulnerability patterns to identify potential weaknesses.
    *   **Validation (`SkepticAgent`):** To minimize false positives, this agent critically reviews the initial findings, assessing exploitability and business logic context.
    *   **Exploit Planning (`ExploiterAgent`):** For high-confidence vulnerabilities, this agent devises a step-by-step plan to exploit the weakness.
    *   **PoC Generation (`GeneratorAgent`):** Translates the exploit plan into a runnable **Foundry** test contract (Proof of Concept).
    *   **Execution & Fixing (`ExploitRunner`):** Automatically runs the generated PoC using Foundry. If the test fails, it attempts to **fix the exploit code** using the LLM and retries (up to a configurable limit).
4.  **Output:** The system reports the validated vulnerabilities, generated PoC code, execution results (success/failure, fix attempts), and optionally generates Markdown/JSON reports.

---

## Core Features

*   **Multi-Agent LLM Workflow:** Specialized agents collaborate for detection, validation, and exploit generation.
*   **Static Analysis Integration:** Leverages Slither for robust initial code understanding.
*   **RAG Enhancement (Optional):** Improves detection by comparing against a knowledge base of known vulnerabilities (via Pinecone).
*   **Multi-Contract Project Analysis:** Understands and analyzes interactions between multiple contracts in a project.
*   **Blockchain Integration:** Can fetch and analyze contracts directly from Ethereum, BSC, Base, and Arbitrum.
*   **Automatic PoC Generation:** Creates Foundry test files demonstrating exploits.
*   **Self-Correcting PoC Execution:** Automatically runs and attempts to fix generated exploit code.
*   **Flexible LLM Configuration:** Supports various models (OpenAI, Anthropic, etc.) and allows different models per agent.
*   **Detailed Reporting:** Provides console output, Markdown reports, and JSON exports.
*   **Performance Tracking:** Logs token usage and execution time for analysis.

---

## Architecture Deep Dive

The system combines static analysis tools with a chain of LLM agents coordinated by the `AgentCoordinator`.

```mermaid
graph TB
    %% Input
    input["Contract Source (File/Dir/Address)"] --> main["main.py (CLI)"]

    %% Core Components
    main --> coord["AgentCoordinator"]

    subgraph "Static Analysis"
        slither["Slither Analyzer"]
        call_graph["Call Graph Generator"]
        contract_parser["Contract Parser"]
    end

    subgraph "Knowledge Base (RAG)"
        pinecone["Pinecone Vector DB (Optional)"]
        vuln_db["Known Vulnerabilities DB"]
    end

    subgraph "Agent Pipeline"
        direction LR
        project_context["ProjectContextLLMAgent"]
        analyzer["AnalyzerAgent"]
        skeptic["SkepticAgent"]
        exploiter["ExploiterAgent"]
        generator["GeneratorAgent"]
        runner["ExploitRunner (w/ Foundry)"]

        project_context --> analyzer
        analyzer --> |"Potential Vulns"| skeptic
        skeptic --> |"Validated Vulns"| exploiter
        exploiter --> |"Exploit Plan"| generator
        generator --> |"PoC Code"| runner
    end

    %% Data Flow
    main --> contract_parser
    contract_parser --> slither
    slither --> call_graph
    slither --> |"AST, Findings"| coord

    coord --> project_context
    project_context --> |"Context Insights"| analyzer
    coord --> analyzer

    vuln_db --> pinecone
    pinecone --> analyzer

    coord --> skeptic
    coord --> exploiter
    coord --> generator
    coord --> runner

    %% Model Configuration
    config["ModelConfig"] --> coord

    %% External Services
    subgraph "LLM Services"
        llm_api["LLM API (OpenAI, Anthropic, etc.)"]
    end

    analyzer --> llm_api
    skeptic --> llm_api
    exploiter --> llm_api
    generator --> llm_api
    runner --> |"Fix Request"| llm_api
    project_context --> llm_api

    %% Output
    runner --> |"Execution Results"| coord
    coord --> |"Final Report"| output["Console Output / Files"]

    %% Styling
    style main fill:#cde4ff,stroke:#000
    style coord fill:#e6b3ff,stroke:#000
    style input fill:#d9ead3,stroke:#000
    style output fill:#fff2cc,stroke:#000
    style slither fill:#fce5cd,stroke:#000
    style call_graph fill:#fce5cd,stroke:#000
    style contract_parser fill:#fce5cd,stroke:#000
    style pinecone fill:#d9d2e9,stroke:#000
    style vuln_db fill:#d9d2e9,stroke:#000
    style analyzer fill:#b3d9ff,stroke:#000
    style skeptic fill:#b3d9ff,stroke:#000
    style exploiter fill:#b3d9ff,stroke:#000
    style generator fill:#b3d9ff,stroke:#000
    style runner fill:#b3d9ff,stroke:#000
    style project_context fill:#b3d9ff,stroke:#000
    style llm_api fill:#d0e0e3,stroke:#000
    style config fill:#f4cccc,stroke:#000
```

*   **Static Analysis:** `slither-analyzer` parses the code, identifies structure, and runs basic detectors.
*   **RAG System:** If enabled (`--no-rag` not used), the `AnalyzerAgent` queries Pinecone (populated with `known_vulnerabilities/contract_vulns.json`) for similar known issues to improve context.
*   **Agent Pipeline:** The `AgentCoordinator` passes the contract info and context through the specialized agents (`Analyzer`, `Skeptic`, `Exploiter`, `Generator`, `Runner`). Each agent uses LLMs via the configured `ModelConfig`.
*   **Foundry Integration:** The `ExploitRunner` uses `forge test` to execute the generated PoC `.sol` files located in the `exploit/` directory.

---

## Prerequisites

Before you begin, ensure you have the following installed and configured:

1.  **Python:** Version 3.8 or higher.
2.  **pip:** Python package installer.
3.  **Git:** For cloning the repository.
4.  **Solidity Compiler & Version Manager (`solc-select`):** Required by Slither to compile contracts. Install it via pip:
    ```bash
    pip install solc-select
    solc-select install 0.8.0 # Or other versions needed by contracts
    solc-select use 0.8.0   # Set a default version
    ```
5.  **Slither:** Smart contract static analyzer. Follow the official [Slither installation guide](https://github.com/crytic/slither#installation). Often requires Node.js/npm for certain dependencies. Like the OpenZeppelin contracts
6.  **Foundry:** Fast, portable, and modular toolkit for Ethereum application development (used for PoC execution). Install via:
    ```bash
    curl -L https://foundry.paradigm.xyz | bash
    foundryup
    ```
    Verify installation: `forge --version`
7.  **API Keys:**
    *   **LLM Provider:** At least one API key (e.g., OpenAI, Anthropic) saved in your environment. See [Installation](#set-up-environment-variables).
    *   **(Optional) Blockchain Explorer:** API keys for Etherscan, BscScan, BaseScan, ArbiScan if using the `--contract-address` feature. Add these to your `.env` file (e.g., `ETHERSCAN_API_KEY=YourKey`).
    *   **(Optional) Pinecone:** API key and environment name if using the RAG feature with Pinecone. Add `PINECONE_API_KEY` and `PINECONE_ENV` to your `.env` file.

---

## Installation & Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/AuditAgent.git # Replace with your repo URL
    cd AuditAgent
    ```

2.  **Initialize Foundry Project & Submodules:**
    The generated exploits rely on Foundry's standard library (`forge-std`). Initialize the `exploit` directory as a Foundry project and pull the necessary submodule:
    ```bash
    cd exploit
    forge init --no-git # Initialize Foundry without creating a new git repo
    git submodule update --init --recursive # Pull forge-std defined in .gitmodules
    cd ..
    ```
    *(Note: If `forge init` complains about an existing directory, you might need to remove the `exploit/lib` directory first if it exists.)*

3.  **Create Python Virtual Environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate # On Windows use `.venv\Scripts\activate`
    ```

4.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Set Up Environment Variables:**
    Create a `.env` file in the project root directory (`AuditAgent/`). Add your API keys:
    ```dotenv
    # --- LLM Keys ---
    OPENAI_API_KEY="sk-YourOpenAIKeyHere"
    # ANTHROPIC_API_KEY="YourAnthropicKeyHere" # If using Claude models
    # DEEPSEEK_API_KEY="YourDeepSeekKeyHere" # If using DeepSeek models

    # --- Blockchain Explorer Keys (Optional - for fetching contracts) ---
    # ETHERSCAN_API_KEY="YourEtherscanKeyHere"
    # BSCSCAN_API_KEY="YourBscScanKeyHere"
    # BASESCAN_API_KEY="YourBaseScanKeyHere"
    # ARBISCAN_API_KEY="YourArbiScanKeyHere"

    # --- Pinecone Key (Optional - for RAG) ---
    # PINECONE_API_KEY="YourPineconeKeyHere"
    # PINECONE_ENV="YourPineconeEnvironmentHere" # e.g., us-west1-gcp
    ```
    *Only include keys for the services you intend to use.*

6.  **Initialize Pinecone Index (Optional - for RAG):**
    If you plan to use the RAG feature (`--no-rag` is *not* specified), you need to populate the Pinecone index. This typically involves running a separate script (check `rag/doc_db.py` or similar) to process the `known_vulnerabilities/contract_vulns.json` file and upload embeddings. Ensure your `.env` file has `PINECONE_API_KEY` and `PINECONE_ENV`. The system might attempt to create the index (`fyp` by default) if it doesn't exist when first run with RAG enabled.

7.  **Verify Installations:**
    *   `python --version`
    *   `pip --version`
    *   `slither --version`
    *   `forge --version`
    *   `solc-select use 0.8.0` (or your desired version)
    *   `solc --version`

---

## Running an Analysis

Execute the main script from the project's root directory (`AuditAgent/`).

**1. Analyzing a Local Contract File:**

```bash
python main.py --contract examples/VulnerableLendingContract.sol
```

**2. Analyzing a Local Multi-File Project Directory:**

Provide the path to the directory containing your `.sol` files. AuditAgent will use Slither to analyze the project structure and the `ProjectContextLLMAgent` to understand inter-contract relationships.

```bash
# Assumes MyProject/ contains ContractA.sol, ContractB.sol, IContract.sol etc.
python main.py --contract path/to/MyProject/
```
*The system will attempt to identify a primary contract file within the directory for context but analyzes all files for interactions.*

**3. Fetching and Analyzing a Contract from Blockchain:**

```bash
# Analyze a contract on Ethereum mainnet
python main.py --contract-address 0xYourContractAddressHere --network ethereum

# Analyze on Base and save preserve project structure for Project Context Agent (if multi-file source)
python main.py --contract-address 0xAnotherAddressHere --network base --save-separate
```
*Requires the relevant Blockchain Explorer API key in your `.env` file.*

**4. Using Specific Models:**

```bash
# Use GPT-4o for all agents
python main.py --all-models o3-mini --contract benchmark_data/contracts/with_errors/access_control/Voting.sol

# Use different models for different agents
python main.py \
  --analyzer-model claude-3-7-sonnet-latest \
  --skeptic-model o3-mini \
  --generator-model claude-3-7-sonnet-latest \
  --contract benchmark_data/contracts/with_errors/access_control/Voting.sol
```

**5. Controlling PoC Generation and Execution:**

```bash
# Analyze but don't generate PoC code (stops after exploit plan)
python main.py --skip-poc --contract examples/VulnerableLendingContract.sol

# Generate PoC but don't run it automatically
python main.py --no-auto-run --contract examples/VulnerableLendingContract.sol

# Generate and run, allow more fix attempts if it fails
python main.py --max-retries 5 --contract examples/VulnerableLendingContract.sol
```

**6. Disabling RAG:**

If you don't have Pinecone set up or want to analyze without the knowledge base:

```bash
python main.py --no-rag --contract examples/VulnerableLendingContract.sol
```

**7. Exporting Results:**

```bash
# Export a Markdown report
python main.py --export-md --contract examples/VulnerableLendingContract.sol

# Export results to a specific JSON file
python main.py --export-json analysis_results.json --contract examples/VulnerableLendingContract.sol
```

---

## Command-Line Flags Explained

| Flag                    | Argument Type          | Default                               | Description                                                                                                                               |
| :---------------------- | :--------------------- | :------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------- |
| `--contract`            | `path`                 | `examples/VulnerableLendingContract.sol` | Path to the local Solidity file **or** directory containing the project to analyze.                                                       |
| `--contract-address`    | `string`               | None                                  | Fetches contract source code from the specified blockchain address. Use with `--network`. Overrides `--contract` if both are provided. |
| `--network`             | `string`               | `ethereum`                            | Blockchain network to use when fetching (`ethereum`, `bsc`, `base`, `arbitrum`).                                                          |
| `--save-separate`       | (flag)                 | False                                 | When fetching a multi-file contract (`--contract-address`), also save the individual `.sol` files to a `_contracts` subdirectory.      |
| `--analyzer-model`      | `string`               | `o3-mini`                             | LLM model name for the AnalyzerAgent.                                                                                                     |
| `--skeptic-model`       | `string`               | `o3-mini`                             | LLM model name for the SkepticAgent.                                                                                                      |
| `--exploiter-model`     | `string`               | `o3-mini`                             | LLM model name for the ExploiterAgent.                                                                                                    |
| `--generator-model`     | `string`               | `o3-mini`                             | LLM model name for the GeneratorAgent (and for fixing PoCs).                                                                              |
| `--context-model`       | `string`               | `o3-mini`                             | LLM model name for the ProjectContextLLMAgent.                                                                                            |
| `--all-models`          | `string`               | None                                  | Use this specified LLM model for *all* agents, overriding individual settings.                                                            |
| `--api-base`            | `url`                  | None                                  | Custom base URL for the LLM API (e.g., for proxies or local models compatible with OpenAI API spec).                                        |
| `--no-rag`              | (flag)                 | False                                 | Disable Retrieval-Augmented Generation. The AnalyzerAgent will not query the Pinecone knowledge base.                                     |
| `--skip-poc`            | (flag)                 | False                                 | Stop the analysis after the `ExploiterAgent` generates the plan. Do not generate or run PoC code.                                          |
| `--no-auto-run`         | (flag)                 | False                                 | Generate PoC code but do not automatically execute it using Foundry.                                                                      |
| `--max-retries`         | `integer`              | `3`                                   | Maximum number of times the `ExploitRunner` will attempt to fix a failing PoC test using the LLM.                                          |
| `--export-md`           | (flag)                 | False                                 | Generate a detailed analysis report in Markdown format in the root directory.                                                              |
| `--export-json`         | `path`                 | None                                  | Export detailed analysis results (vulnerabilities, PoCs, execution status) to the specified JSON file path.                                |

---

## Understanding the Output

AuditAgent generates several outputs:

1.  **Console Output:**
    *   Real-time progress updates from each agent.
    *   Configuration details.
    *   Static analysis findings summary.
    *   Detected vulnerabilities with confidence scores and reasoning.
    *   PoC generation status and file paths.
    *   PoC execution results (`SUCCESS`/`FAILED`, retries, errors).
    *   Final performance metrics (token usage, time).

2.  **Generated Files:**
    *   **Proof of Concept (PoC) Files:**
        *   **Location:** `exploit/src/test/`
        *   **Naming:** `PoC_<VulnerabilityType>_<Timestamp>.sol`
        *   **Content:** A Foundry test contract designed to exploit a specific vulnerability. Imports `basetest.sol`.
        *   **Base Test File:** `exploit/src/test/basetest.sol` is generated if it doesn't exist. It provides helper functions and logging for the PoCs.
    *   **Markdown Report (`--export-md`):**
        *   **Location:** Project root directory.
        *   **Naming:** `analysis_report_<ContractName>_<Timestamp>.md`
        *   **Content:** A comprehensive report including contract details, vulnerability summary table, detailed analysis for each vulnerability (reasoning, code snippets, exploit plan), PoC status, and general recommendations.
    *   **JSON Report (`--export-json <path>`):**
        *   **Location:** Path specified by the user.
        *   **Content:** Structured data containing all analysis results, including vulnerability details, PoC plans, generated code paths, and execution status. Useful for programmatic integration.
    *   **Fetched Contract Files (if using `--contract-address`):**
        *   **Location:** `uploads/` directory by default.
        *   **Naming:** `<ContractAddress>_<Network>.sol` (flattened)
        *   **Subdirectory (if `--save-separate`):** `uploads/<ContractAddress>_<Network>_contracts/` containing individual source files.
    *   **Performance Metrics:**
        *   **Location:** Project root directory.
        *   **Naming:** `performance_metrics_<Timestamp>.json`
        *   **Content:** Detailed breakdown of LLM token usage per agent/model, code metrics (lines analyzed), and time taken per stage.

3.  **Interpreting Results:**
    *   **Confidence Scores:** Pay close attention to the `skeptic_confidence` score (0.0 - 1.0). Higher scores indicate greater certainty after validation. Scores > 0.5 typically warrant investigation.
    *   **Reasoning & Validation:** Read the `reasoning` (initial finding) and `validity_reasoning` (skeptic's assessment) to understand *why* something is flagged.
    *   **PoC Status:**
        *   `SUCCESS`: The generated exploit worked as intended.
        *   `FAILED`: The exploit failed, even after fix attempts. Review the error and the PoC code (`exploit/src/test/...`).
        *   `SKIPPED`: PoC generation or execution was disabled (`--skip-poc` or `--no-auto-run`).

---

## Automatic PoC Execution & Fixing

A key feature is the `ExploitRunner`'s ability to test and self-correct generated PoCs:

1.  **Execution:** After `GeneratorAgent` creates a `.sol` file in `exploit/src/test/`, the `ExploitRunner` executes `forge test --match-path <PoC_File_Path>` within the `exploit/` directory.
2.  **Error Detection:** If the `forge test` command fails (non-zero exit code or specific failure patterns in output), the runner extracts the relevant error messages from `stdout`/`stderr`.
3.  **LLM Correction:** The failing code, along with the error message, is sent back to the LLM (using the `generator_model`) with a prompt asking it to fix the code.
4.  **Retry:** The corrected code overwrites the original PoC file, and the `forge test` command is executed again.
5.  **Loop:** This process repeats up to `--max-retries` times (default 3).
6.  **Reporting:** The final status (SUCCESS or FAILED), the number of retries, and the last error message (if failed) are reported.

This loop helps overcome common LLM generation errors (syntax issues, incorrect logic, missing imports, setup problems like insufficient funds) automatically.

---

## Troubleshooting

*   **`Slither analysis failed`:**
    *   Ensure Slither is correctly installed (`slither --version`).
    *   Check if the Solidity version used by the contract is installed via `solc-select` (`solc-select install <version>`) and selected (`solc-select use <version>`).
    *   Verify contract code syntax. Slither needs compilable code.
    *   If analyzing a project directory, ensure import paths are resolvable or provide necessary remappings (though Slither handles many common ones like OpenZeppelin). Check Slither's documentation for complex project structures.
*   **`API Key Error` / `AuthenticationError`:**
    *   Verify your API key is correct in the `.env` file (e.g., `OPENAI_API_KEY="..."`).
    *   Ensure the `.env` file is in the project's root directory.
    *   Make sure you have activated the virtual environment (`source .venv/bin/activate`).
    *   Check if the correct environment variable name is used for your LLM provider (e.g., `ANTHROPIC_API_KEY`).
*   **`Foundry command not found` / `forge: command not found`:**
    *   Ensure Foundry is installed correctly and its binaries (`forge`, `cast`, etc.) are in your system's PATH. Run `foundryup` again if needed.
    *   Verify you are running the script from the project root directory. The `ExploitRunner` executes `forge` within the `exploit/` subdirectory.
*   **PoC Tests Fail (`Execution: FAILED`):**
    *   Check the error message printed in the console output or the Markdown/JSON report.
    *   Examine the generated PoC file in `exploit/src/test/`. Common issues include:
        *   Incorrect contract addresses or setup in the `setUp()` function.
        *   Insufficient ETH dealt to the attacker contract (`vm.deal`).
        *   Logical errors in the `testExploit()` function sequence.
        *   Compatibility issues if the LLM generated code for a different Solidity/Foundry version.
    *   Try increasing `--max-retries` if it fails after the default attempts.
*   **RAG Errors / Pinecone Issues:**
    *   Ensure `PINECONE_API_KEY` and `PINECONE_ENV` are correct in `.env`.
    *   Verify the Pinecone index exists and has the correct dimensions (usually 1536 for OpenAI embeddings).
    *   Check network connectivity to Pinecone.
    *   Run with `--no-rag` to bypass the knowledge base if Pinecone setup is problematic.
*   **Slow Performance / High Token Usage:**
    *   Consider using smaller/faster models (like `o3-mini`, `claude-3-haiku`) for some agents, especially the Skeptic or Exploiter.
    *   Use `--skip-poc` if you only need the analysis and exploit plan.
    *   Check the `performance_metrics_...json` file to see which agents/models consume the most tokens/time.

```
