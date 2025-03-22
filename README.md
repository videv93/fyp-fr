# Generate Vulnerable Transaction Sequences for Smart Contract using Large Language Models

This project utilises a multi-agent workflow to identify vulnerabilities and generate transactions to exploit them. In future iterations we will run these exploits in a sandbox VM to demonstrate them.

https://github.com/user-attachments/assets/8360a8b6-4ca0-49d3-be3c-94c195b3c5a3


## Component Documentation

| Component | Description | Detailed Documentation |
|-----------|-------------|----------------------|
| Static Analysis | Contract parsing and vulnerability detection using Slither | [README_STATIC_ANALYSIS.md](README_STATIC_ANALYSIS.md) |
| LLM Agents | Multi-agent system for vulnerability analysis and exploit generation | [README_LLM_AGENTS.md](README_LLM_AGENTS.md) |
| RAG System | Retrieval-Augmented Generation for enhanced vulnerability detection | [README_RAG.md](README_RAG.md) |

## Features

- **Static Analysis**: Utilizes Slither to parse and analyze Solidity contracts, extracting function details and generating call graphs.
- **Knowledge Base**: Stores vulnerability information using FAISS for efficient similarity searches, enabling contextual analysis.
- **LLM Integration**: Supports multiple LLM providers (OpenAI, Anthropic, Ollama) with automatic prompt format optimization.
- **Agent Coordination**: Coordinates between analysis agents to provide comprehensive vulnerability assessments and exploit recommendations.
- **Model Flexibility**: Configure different models for each agent based on task complexity and performance requirements.
- **Project Context Analysis**: Employs an LLM-powered agent to analyze inter-contract relationships and provide contextual insights for vulnerability detection.
- **Multi-Contract Analysis**: Supports the analysis of multiple contracts within a project, identifying potential vulnerabilities arising from their interactions.

## Architecture

The project implements a multi-agent system for smart contract vulnerability detection and exploit generation, utilizing Retrieval-Augmented Generation (RAG) and a coordinated pipeline of specialized agents. Here's how the system works:

1. **Static Analysis & RAG System**:
   - Parses Solidity contracts using Slither for initial static analysis
   - Maintains a knowledge base of known vulnerabilities in Pinecone Vector DB
   - Uses RAG to enhance vulnerability detection with historical context

2. **Agent Pipeline**:
   - **AgentCoordinator**: Orchestrates the multi-agent workflow and manages agent interactions
   - **ProjectContextLLMAgent**: Analyzes inter-contract relationships and provides contextual insights for vulnerability detection
   - **Analysis Flow**:
     1. AnalyzerAgent: Initial vulnerability detection using RAG and LLM analysis
     2. SkepticAgent: Validates findings to reduce false positives
     3. ExploiterAgent: Generates exploit strategies for confirmed vulnerabilities
     4. GeneratorAgent: Creates concrete PoC exploits
     5. ExploitRunner: Executes and validates the generated exploits

```mermaid
graph TB
    %% Core Components
    contract["Smart Contract"] --> coord["AgentCoordinator"]
    
    subgraph "Knowledge Base"
        pinecone["Pinecone Vector DB"]
        vulncat["Vulnerability Categories"]
        known_vulns["Known Vulnerabilities"]
    end

    subgraph "Agent Pipeline"
        direction LR
        project_context["ProjectContextLLMAgent"]
        analyzer["AnalyzerAgent"]
        skeptic["SkepticAgent"]
        exploiter["ExploiterAgent"]
        generator["GeneratorAgent"]
        runner["ExploitRunner"]
        
        project_context --> analyzer
        analyzer --> |"Potential Vulns"| skeptic
        skeptic --> |"Validated Vulns"| exploiter
        exploiter --> |"Exploit Plan"| generator
        generator --> |"PoC Code"| runner
    end

    %% RAG System Integration
    pinecone --> analyzer
    vulncat --> analyzer
    known_vulns --> pinecone

    %% Coordinator Flow
    coord --> project_context
    coord --> analyzer
    coord --> skeptic
    coord --> exploiter
    coord --> generator
    coord --> runner

    %% Model Configuration
    config["ModelConfig"] --> coord
    
    %% External Services
    subgraph "LLM Services"
        openai["OpenAI API"]
    end
    
    analyzer --> openai
    skeptic --> openai
    exploiter --> openai
    generator --> openai

    %% Output
    runner --> |"Execution Results"| coord
    coord --> |"Final Report"| output["Vulnerability Report"]

    style coord fill:#e6b3ff,stroke:#000,stroke-width:2px,color:#000
    style analyzer fill:#b3d9ff,stroke:#000,color:#000
    style skeptic fill:#b3d9ff,stroke:#000,color:#000
    style exploiter fill:#b3d9ff,stroke:#000,color:#000
    style generator fill:#b3d9ff,stroke:#000,color:#000
    style runner fill:#b3d9ff,stroke:#000,color:#000
    style project_context fill:#b3d9ff,stroke:#000,color:#000
    style contract fill:#d9f2d9,stroke:#000,color:#000
    style output fill:#ffe6cc,stroke:#000,color:#000
    style config fill:#ffcccc,stroke:#000,color:#000
    
    style pinecone fill:#ffecb3,stroke:#000,color:#000
    style vulncat fill:#ffecb3,stroke:#000,color:#000
    style known_vulns fill:#ffecb3,stroke:#000,color:#000
    style openai fill:#e6ffcc,stroke:#000,color:#000
```

3. **Key Features**:
   - **Configurable Models**: Each agent can use different LLM models based on task requirements
   - **RAG Enhancement**: Uses similar historical vulnerabilities to improve detection accuracy
   - **Progressive Validation**: Multi-stage verification process reduces false positives
   - **Automated Exploitation**: Generates and validates concrete exploit code

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

   Basic usage with default models (o1-mini):
   ```bash
   python main.py --contract path/to/your/contract.sol
   ```

   Configure which models to use for each agent:
   ```bash
   # Use the same model for all agents
   python main.py --all-models gpt-4o --contract path/to/your/contract.sol

   # Configure individual agents with different models
   python main.py \
     --analyzer-model gpt-4o \
     --skeptic-model gpt-3.5-turbo \
     --exploiter-model claude-3-haiku-20240307 \
     --generator-model o1-preview \
     --contract path/to/your/contract.sol

   # Configure API base URL (useful for proxies)
   python main.py --api-base https://your-proxy.com/v1 --all-models gpt-4
   ```

   Auto-run execution options:
   ```bash
   # Disable automatic execution of PoCs
   python main.py --no-auto-run --contract path/to/your/contract.sol

   # Set maximum number of fix attempts for failing tests
   python main.py --max-retries 5 --contract path/to/your/contract.sol
   ```

   The script will:

   - Parse the Solidity contract using Slither.
   - Extract function details and generate a call graph.
   - Analyze the contract against the knowledge base for known vulnerabilities.
   - Use LLM agents to generate a comprehensive vulnerability report and exploit plan.

4. **View Results**

   The analysis results will be printed to the console, detailing detected vulnerabilities, confidence scores, reasoning, and suggested exploit transactions.

## Automatic PoC Execution and Fixing

The system includes a self-correction mechanism for generated proof-of-concept exploits:

### Features
- **Auto-run**: Automatically executes generated PoC tests after creation
- **Error Detection**: Intelligently identifies and extracts error information from test failures
- **Self-correction**: Uses the same LLM to fix broken test code based on error messages
- **Multiple Retries**: Attempts up to 3 fixes by default (configurable with `--max-retries`)
- **Detailed Reporting**: Reports execution status, error messages, and fix attempts

### Troubleshooting Common Issues
The system automatically addresses common errors in generated tests:
- Missing funds for transactions (adding vm.deal statements)
- Incorrect function calls or parameters
- Arithmetic errors like overflow/underflow
- State inconsistencies across transactions
- Solidity version compatibility issues
- Import errors and contract initialization problems
