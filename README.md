# LLM Agents for Smart Contract Vulnerability Analysis

![Project Logo](static_analysis/logo.png) <!-- Optional: Add a project logo -->

## Features

- **Static Analysis**: Utilizes Slither to parse and analyze Solidity contracts, extracting function details and generating call graphs.
- **Knowledge Base**: Stores vulnerability information using FAISS for efficient similarity searches, enabling contextual analysis.
- **LLM Integration**: Employs OpenAI's GPT-3.5-turbo to analyze detected vulnerabilities and propose exploit strategies.
- **Agent Coordination**: Coordinates between analysis agents to provide comprehensive vulnerability assessments and exploit recommendations.

## Architecture

The project is divided into two main components:

1. **Static Analysis**: Parses and analyzes Solidity contracts to extract detailed information and detect potential issues.
2. **LLM Agents**: Uses language models to interpret static analysis results, identify vulnerabilities, and suggest exploit strategies.

## Prerequisites

- Python 3.8+
- Solidity Compiler (for Slither)
- OpenAI API Key
- [Slither](https://github.com/crytic/slither) installed

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/your-username/llm_agents.git
   cd llm_agents
   ```

2. **Create a Virtual Environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up Slither**

   Follow the [Slither installation guide](https://github.com/crytic/slither#installation) to install Slither and its dependencies.

5. **Set Up Environment Variables**

   Create a `.env` file in the project root and add your OpenAI API key:

   ```env
   OPENAI_API_KEY=your_openai_api_key_here
   ```

   Alternatively, export it directly in your shell:

   ```bash
   export OPENAI_API_KEY=your_openai_api_key_here
   ```

## Usage

1. **Prepare Solidity Contracts**

   Place your Solidity contracts in the `static_analysis/test_contracts/` directory. Sample contracts are provided for testing purposes.

2. **Set your Solidity Compiler Version**

    Based on the Solidity version used in your contracts, install the corresponding compiler version using `solc-select`:

    ```python
    solc-select install 0.8.0
    solc-select use 0.8.0
    ```

3. **Run the Analysis**

   Execute the main script to perform static analysis and vulnerability assessment:

   ```bash
   python main.py
   ```

   The script will:

   - Parse the Solidity contract using Slither.
   - Extract function details and generate a call graph.
   - Analyze the contract against the knowledge base for known vulnerabilities.
   - Use LLM agents to generate a comprehensive vulnerability report and exploit plan.

4. **View Results**

   The analysis results will be printed to the console, detailing detected vulnerabilities, confidence scores, reasoning, and suggested exploit transactions.

## Project Structure

```
fyp-fr/
├── llm_agents/
│   ├── __init__.py
│   ├── agent_coordinator.py
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   ├── exploiter.py
│   │   └── generator.py
│   └── __pycache__/
├── rag/
│   ├── __init__.py
│   ├── knowledge_base.py
│   ├── vectorstore.py
│   └── __pycache__/
├── static_analysis/
│   ├── __init__.py
│   ├── call_graph_printer.py
│   ├── parse_contract.py
│   ├── slither_detectors.py
│   ├── test_contracts/
│   │   ├── code.sol
│   │   ├── reentrancy.sol
│   │   ├── slither_demo.sol
│   │   └── token.sol
│   └── __pycache__/
├── main.py
├── requirements.txt
└── README.md
```

## Knowledge Base

The knowledge base stores predefined vulnerability documents with detailed descriptions, scenarios, properties, impacts, code patterns, prevention measures, and exploit templates. It uses FAISS for efficient similarity searches, allowing the system to retrieve relevant vulnerability information based on the analysis results.

- **File**: `rag/knowledge_base.py`
- **Data**: `VULNERABILITY_DOCS` list containing instances of `VulnerabilityDoc` dataclass.

## Static Analysis

Static analysis is performed using Slither, which parses Solidity contracts to extract function details, generate call graphs, and detect common vulnerabilities.

- **Parser**: `static_analysis/parse_contract.py`
- **Call Graph Generation**: `static_analysis/call_graph_printer.py`
- **Custom Detectors**: `static_analysis/slither_detectors.py` defines a comprehensive list of Slither detectors used for vulnerability detection.

### Running Static Analysis

Static analysis is integrated into the main script (`main.py`). To perform analysis on a specific contract, place it in the `static_analysis/test_contracts/` directory and update the `filepath` variable in `main.py` if necessary.

## LLM Agents

LLM Agents leverage OpenAI's GPT-3.5-turbo model to interpret static analysis results, identify vulnerabilities, and suggest exploit strategies. The coordination between different agents ensures a comprehensive analysis pipeline.

- **Coordinator**: `llm_agents/agent_coordinator.py` orchestrates the workflow between analyzer, exploiter, and generator agents.
- **Agents**:
  - **AnalyzerAgent**: Analyzes function details and retrieves relevant vulnerability patterns from the knowledge base.
  - **ExploiterAgent**: Plans exploit strategies based on identified vulnerabilities.
  - **GeneratorAgent**: Generates concrete transaction sequences for exploit execution.

### Workflow

1. **Analyze Contract**: Extract function details and identify potential vulnerabilities.
2. **Plan Exploit**: Based on vulnerabilities, devise exploit strategies.
3. **Generate Transactions**: Create detailed transaction sequences to execute the exploit.
