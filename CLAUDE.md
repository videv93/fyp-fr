# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SmartGuard** is an LLM-powered smart contract vulnerability analyzer that uses a multi-agent workflow to detect vulnerabilities and generate proof-of-concept exploits. The system combines static analysis (Slither) with specialized LLM agents and optional RAG (Retrieval-Augmented Generation) to analyze Solidity contracts.

**User:** vitr (prefers clarifying questions over assumptions)

## Core Architecture

### Multi-Agent Pipeline

The system uses a coordinated agent workflow managed by `AgentCoordinator` (llm_agents/agent_coordinator.py):

1. **ProjectContextLLMAgent** (`llm_agents/agents/project_context_llm.py`): Analyzes multi-contract projects to understand inter-contract relationships and dependencies
2. **AnalyzerAgent** (`llm_agents/agents/analyzer.py`): Identifies potential vulnerabilities using static analysis results and optional RAG
3. **SkepticAgent** (`llm_agents/agents/skeptic.py`): Validates findings to reduce false positives, assesses exploitability
4. **ExploiterAgent** (`llm_agents/agents/exploiter.py`): Creates step-by-step exploit plans for high-confidence vulnerabilities
5. **GeneratorAgent** (`llm_agents/agents/generator.py`): Generates Foundry test contracts (PoCs) from exploit plans
6. **ExploitRunner** (`llm_agents/agents/runner.py`): Executes PoCs using Foundry and attempts self-correction on failures

### Static Analysis Layer

- **Slither Integration**: `static_analysis/parse_contract.py` uses Slither to extract function details, call graphs, and detector results
- **Contract Parsing**: `static_analysis/extract_contracts.py` handles multi-file projects
- **Call Graph Generation**: `static_analysis/call_graph_printer.py` creates function call relationships
- **Detector Results**: `static_analysis/slither_detectors.py` processes Slither's built-in detectors

### RAG System

- **Vector DB**: `rag/doc_db.py` manages Pinecone vector database with known vulnerabilities from `known_vulnerabilities/contract_vulns.json`
- **Optional Feature**: Can be disabled with `--no-rag` flag if Pinecone is not configured

### Model Configuration

- **ModelConfig** (`llm_agents/config.py`): Centralized configuration for all agent models
- **Multi-Provider Support**:
  - OpenAI (o3-mini, gpt-4o)
  - Anthropic (claude-3-5-haiku-latest, claude-3-7-sonnet-latest)
  - DeepSeek (deepseek-chat, deepseek-reasoner)
  - Google Gemini (models/gemini-2.5-flash, models/gemini-2.5-pro, models/gemini-2.0-flash, models/gemini-1.5-flash, models/gemini-1.5-pro)
- **Reasoning Models**: o3-mini, o1-mini, deepseek-reasoner use specialized reasoning prompts
- **Per-Agent Configuration**: Each agent can use a different model for optimal performance/cost tradeoffs

## Common Development Commands

### Environment Setup

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install Solidity compiler
pip install solc-select
solc-select install 0.8.0
solc-select use 0.8.0

# Install Foundry (for PoC execution)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Initialize Foundry in exploit directory
cd exploit
forge init --no-git
git submodule update --init --recursive
cd ..
```

### Environment Variables

Create `.env` file in project root with required API keys:
- `OPENAI_API_KEY` - Required for OpenAI models (default: o3-mini)
- `ANTHROPIC_API_KEY` - Required if using Claude models
- `DEEPSEEK_API_KEY` - Required if using DeepSeek models
- `GOOGLE_API_KEY` - Required if using Gemini models
- `PINECONE_API_KEY`, `PINECONE_ENV` - Optional, for RAG functionality
- `ETHERSCAN_API_KEY`, `BSCSCAN_API_KEY`, `BASESCAN_API_KEY`, `ARBISCAN_API_KEY` - Optional, for fetching contracts from blockchain

See `.env.example` for template.

### Running Analysis

```bash
# Basic analysis of a local contract
python main.py --contract examples/VulnerableLendingContract.sol

# Analyze a directory with multiple contracts
python main.py --contract path/to/project/

# Fetch and analyze from blockchain
python main.py --contract-address 0xYourAddress --network ethereum --save-separate

# Use specific models for agents
python main.py --all-models o3-mini --contract examples/VulnerableLendingContract.sol
python main.py --analyzer-model claude-3-7-sonnet-latest --skeptic-model o3-mini --contract file.sol

# Use Google Gemini models
python main.py --all-models "models/gemini-2.0-flash" --contract examples/VulnerableLendingContract.sol
python main.py --analyzer-model "models/gemini-2.5-pro" --skeptic-model "models/gemini-2.0-flash" --contract file.sol

# Skip PoC generation (analysis only)
python main.py --skip-poc --contract file.sol

# Generate PoC but don't auto-run
python main.py --no-auto-run --contract file.sol

# Disable RAG
python main.py --no-rag --contract file.sol

# Export reports
python main.py --export-md --export-json results.json --contract file.sol
```

### Testing & Benchmarking

```bash
# Run vulnerability detection benchmark (CTFBench methodology)
python ctfbench_evaluator.py --models o3-mini claude-3-7-sonnet-latest --rag both

# Run exploit generation/execution benchmark
python exploit_success_evaluator.py --models o3-mini --rag both --max-workers 4

# Evaluate specific vulnerability categories
python exploit_success_evaluator.py --categories reentrancy access_control --models o3-mini

# Run on single contract
python exploit_success_evaluator.py --example-contract examples/VulnerableLendingContract.sol
```

### Foundry Commands (PoC Testing)

```bash
# Run all PoC tests
cd exploit
forge test

# Run specific PoC test
forge test --match-path src/test/PoC_Reentrancy_20240101_120000.sol

# Run with verbose output
forge test -vvv

# Clean and rebuild
forge clean && forge build
```

### Frontend Development

```bash
# Backend (Flask server)
cd frontend_poc
pip install flask flask-socketio flask-cors
python app.py

# Frontend (React app)
cd frontend_poc/client
npm install
npm start

# Production build
npm run build
```

## Key File Locations

### Generated Outputs

- **PoC Files**: `exploit/src/test/PoC_<VulnerabilityType>_<Timestamp>.sol`
- **Base Test Helper**: `exploit/src/test/basetest.sol` (auto-generated helper functions)
- **Markdown Reports**: `analysis_report_<ContractName>_<Timestamp>.md` (root directory)
- **JSON Reports**: Custom path specified via `--export-json`
- **Performance Metrics**: `performance_metrics_<Timestamp>.json` (root directory)
- **Fetched Contracts**: `uploads/<ContractAddress>_<Network>.sol`
- **Multi-File Projects**: `uploads/<ContractAddress>_<Network>_contracts/` (if `--save-separate`)

### Benchmark Data

- **Test Contracts**: `benchmark_data/contracts/with_errors/` organized by vulnerability category
- **Evaluation Results**: `benchmark_results/` contains evaluation outputs
- **Known Vulnerabilities**: `known_vulnerabilities/dataset/` categorized vulnerability examples

### Configuration Files

- **Vulnerability Categories**: `vulnerability_categories.json` - defines vulnerability taxonomy
- **Foundry Config**: `exploit/foundry.toml` - Foundry project settings

## Development Guidelines

### Adding New Agents

1. Create agent file in `llm_agents/agents/`
2. Inherit from base patterns in existing agents
3. Register in `AgentCoordinator` (llm_agents/agent_coordinator.py)
4. Add model configuration in `ModelConfig.get_model()` if needed
5. Update command-line arguments in `main.py` if agent needs custom model selection

### Adding New Vulnerability Detectors

1. Add detection logic to `llm_agents/agents/analyzer.py`
2. Update `vulnerability_categories.json` with new category
3. Add examples to `known_vulnerabilities/dataset/<category>/`
4. Update RAG database if using Pinecone: modify `rag/doc_db.py` and re-index

### Working with Static Analysis

- Slither analysis is performed once at the start via `static_analysis/parse_contract.py`
- Results include: function details, call graphs, detector findings
- For multi-contract projects, pass directory path instead of file path
- Slither may require specific Solidity versions: use `solc-select use <version>` before analysis

### Model Configuration Best Practices

- **Fast Analysis**: Use `o3-mini` or `models/gemini-2.0-flash` for all agents
- **High Accuracy**: Use `claude-3-7-sonnet-latest` or `models/gemini-2.5-pro` for analyzer, skeptic, generator
- **Cost Optimization**: Mix models - use Claude/Gemini Pro for critical agents (analyzer, generator), Flash models for others
- **Reasoning Models**: o3-mini, o1-mini, deepseek-reasoner support extended reasoning but may be slower
- **Gemini Models**: Fast and cost-effective, good balance between speed and accuracy. Must use `models/` prefix.

### Performance Tracking

- Token usage tracked per agent and model in `utils/token_tracker.py`
- Performance metrics saved automatically after each run
- Use metrics to optimize model selection and identify bottlenecks
- Files analyzed and LOC counted for context analysis

### PoC Execution & Self-Correction

- `ExploitRunner` automatically tests generated PoCs using `forge test`
- Failed tests trigger LLM-based correction (up to `--max-retries` attempts, default: 3)
- Corrections use the `generator_model` to fix syntax, logic, and setup issues
- Success/failure status and retry count reported in results

### Frontend Integration

- Backend (`frontend_poc/app.py`) wraps main analysis pipeline with Flask + Socket.io
- Real-time updates via WebSocket events: `agent_active`, `agent_status`, `vulnerability_detected`, etc.
- API endpoints in `frontend_poc/app.py` handle contract upload, fetching, and analysis requests
- React frontend in `frontend_poc/client/` provides interactive UI

## Important Patterns

### Contract Fetching vs Local Analysis

- **Local File**: `--contract path/to/file.sol` - single file
- **Local Directory**: `--contract path/to/directory/` - multi-file project, triggers ProjectContextLLMAgent
- **Blockchain Address**: `--contract-address 0x... --network ethereum` - fetches flattened contract
  - Use `--save-separate` to also save individual source files in `_contracts/` subdirectory
  - Multi-file fetched contracts also trigger ProjectContextLLMAgent if `--save-separate` used

### Agent Workflow Control

- All agents run sequentially through coordinator
- `--skip-poc` stops after ExploiterAgent (no generation or execution)
- `--no-auto-run` generates PoC but skips execution
- RAG is queried only by AnalyzerAgent (if enabled)
- ProjectContextLLMAgent only runs for multi-contract projects (directories or fetched with `--save-separate`)

### Error Handling

- Slither failures attempt fallback to flattened file if directory analysis fails
- PoC execution failures trigger automatic correction attempts
- Missing API keys cause early failure with clear error messages
- Performance tracker handles stage transitions gracefully even on errors

## Troubleshooting

### Slither Analysis Fails

- Check Solidity compiler version: `solc --version`
- Install correct version: `solc-select install <version> && solc-select use <version>`
- For multi-file projects, ensure all imports resolve correctly
- Check if contract requires specific libraries (e.g., OpenZeppelin) - may need npm install in contract directory

### PoC Tests Fail

- Examine error message in console output or performance metrics JSON
- Check generated PoC file in `exploit/src/test/`
- Manually run: `cd exploit && forge test --match-path src/test/<PoC_file> -vvv`
- Increase retries: `--max-retries 5`
- Review `basetest.sol` for helper functions

### RAG/Pinecone Errors

- Verify `PINECONE_API_KEY` and `PINECONE_ENV` in `.env`
- Initialize index: may require running `rag/doc_db.py` separately to populate
- Use `--no-rag` to bypass RAG entirely

### API Key/Model Errors

- Check correct API key for model provider in `.env`
- OpenAI models need `OPENAI_API_KEY`
- Claude models need `ANTHROPIC_API_KEY`
- DeepSeek models need `DEEPSEEK_API_KEY`
- Gemini models need `GOOGLE_API_KEY`
- Verify model names match those in `llm_agents/config.py` model_provider dict
- For Gemini models, ensure you include the `models/` prefix (e.g., `models/gemini-2.0-flash`)

### Foundry Not Found

- Install Foundry: `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- Verify installation: `forge --version`
- Initialize exploit directory: `cd exploit && forge init --no-git && git submodule update --init --recursive`
