# LLM Agents for Smart Contract Vulnerability Analysis

## Features

- **Static Analysis**: Utilizes Slither to parse and analyze Solidity contracts, extracting function details and generating call graphs.
- **Knowledge Base**: Stores vulnerability information using FAISS for efficient similarity searches, enabling contextual analysis.
- **LLM Integration**: Employs OpenAI's GPT-3.5-turbo to analyze detected vulnerabilities and propose exploit strategies.
- **Agent Coordination**: Coordinates between analysis agents to provide comprehensive vulnerability assessments and exploit recommendations.

## Architecture

The project is divided into two main components:

1. **Static Analysis**: Parses and analyzes Solidity contracts to extract detailed information and detect potential issues.
2. **LLM Agents**: Uses language models to interpret static analysis results, identify vulnerabilities, and suggest exploit strategies.

```mermaid
graph TB
    subgraph Main Application
        main[main.py]
    end

    subgraph Static Analysis
        parser[parse_contract.py]
        callgraph[call_graph_printer.py]
        detectors[slither_detectors.py]

        parser --> callgraph
        parser --> detectors
    end

    subgraph Knowledge Base
        kb[knowledge_base.py]
        vectorstore[vectorstore.py]
        rules[(YAML Rules)]

        kb --> vectorstore
        rules --> kb
    end

    subgraph LLM Agents
        coordinator[agent_coordinator.py]
        subgraph Agents
            analyzer[analyzer.py]
            exploiter[exploiter.py]
            generator[generator.py]
        end

        coordinator --> analyzer
        coordinator --> exploiter
        coordinator --> generator
    end

    %% External Dependencies
    openai[OpenAI API]
    slither[Slither]
    faiss[FAISS Vector Store]

    %% Main Flow
    main --> parser
    main --> coordinator

    %% Static Analysis Flow
    parser --> slither

    %% Knowledge Base Flow
    vectorstore --> faiss

    %% Agent Flow
    analyzer --> openai
    analyzer --> vectorstore
    exploiter --> openai
    generator --> openai

    %% Data Flow
    parser -- Contract Info --> coordinator
    kb -- Vulnerability Patterns --> analyzer
    analyzer -- Vulnerabilities --> exploiter
    exploiter -- Exploit Plans --> generator

    class main,coordinator,analyzer,exploiter,generator component
    class openai,slither,faiss external
    class rules storage
```

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
