.PHONY: help setup install-solc analyze analyze-all clean

# Default target
help:
	@echo "SmartGuard - Smart Contract Vulnerability Analyzer"
	@echo ""
	@echo "=== Setup & Configuration ==="
	@echo "  make setup              - Set up virtual environment and install dependencies"
	@echo "  make install-solc       - Install Solidity compiler (version 0.8.20)"
	@echo "  make status             - Show environment and API key status"
	@echo ""
	@echo "=== Example Analysis ==="
	@echo "  make analyze FILE=path  - Analyze a specific contract file"
	@echo "  make analyze-examples   - Analyze all example contracts"
	@echo "  make analyze-lending    - Analyze VulnerableLendingContract.sol"
	@echo "  make analyze-reentrancy - Analyze ReentrancyTest.sol"
	@echo "  make analyze-multi      - Analyze MultiContract directory"
	@echo ""
	@echo "=== Audit Contests ==="
	@echo "  make audit-hybra        - Analyze all Hybra Finance in-scope contracts"
	@echo "  make audit-hybra-single CONTRACT=name - Analyze single Hybra contract"
	@echo "  make audit-hybra-ve33   - Analyze Hybra ve33 contracts directory"
	@echo "  make audit-hybra-cl     - Analyze Hybra CL (concentrated liquidity) contracts"
	@echo "  make audit-hybra-results - Show Hybra audit results summary"
	@echo ""
	@echo "=== Testing ==="
	@echo "  make test-foundry       - Run Foundry tests"
	@echo "  make test-foundry-verbose - Run Foundry tests with verbose output"
	@echo ""
	@echo "=== Cleanup ==="
	@echo "  make clean              - Clean generated files"
	@echo "  make clean-all          - Deep clean including exploit tests"
	@echo ""
	@echo "Examples:"
	@echo "  make analyze FILE=examples/VulnerableLendingContract.sol"
	@echo "  make analyze FILE=examples/VulnerableLendingContract.sol MODEL=\"models/gemini-2.0-flash\""
	@echo "  make audit-hybra-single CONTRACT=GaugeV2"

# Variables
VENV = .venv
PYTHON = $(VENV)/bin/python3
PIP = $(VENV)/bin/pip
SOLC_VERSION = 0.8.20
MODEL ?= models/gemini-2.0-flash
FILE ?=

# Setup virtual environment and install dependencies
setup:
	@echo "Setting up virtual environment..."
	python3.12 -m venv $(VENV)
	@echo "Installing dependencies..."
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "✓ Setup complete"

# Install Solidity compiler
install-solc:
	@echo "Installing Solidity compiler version $(SOLC_VERSION)..."
	$(VENV)/bin/solc-select install $(SOLC_VERSION)
	$(VENV)/bin/solc-select use $(SOLC_VERSION)
	@echo "✓ Solidity $(SOLC_VERSION) installed and activated"
	@$(VENV)/bin/solc --version

# Analyze a specific contract
analyze:
	@if [ -z "$(FILE)" ]; then \
		echo "Error: FILE parameter is required"; \
		echo "Usage: make analyze FILE=path/to/contract.sol"; \
		exit 1; \
	fi
	@echo "Analyzing $(FILE) with model $(MODEL)..."
	$(PYTHON) main.py --contract $(FILE) --all-models $(MODEL) --no-rag

# Analyze VulnerableLendingContract example
analyze-lending:
	@echo "Analyzing VulnerableLendingContract.sol..."
	$(PYTHON) main.py --contract examples/VulnerableLendingContract.sol --all-models $(MODEL) --no-rag

# Analyze ReentrancyTest example
analyze-reentrancy:
	@echo "Analyzing ReentrancyTest.sol..."
	$(PYTHON) main.py --contract examples/ReentrancyTest.sol --all-models $(MODEL) --no-rag

# Analyze MultiContract directory
analyze-multi:
	@echo "Analyzing MultiContract directory..."
	$(PYTHON) main.py --contract examples/MultiContract/ --all-models $(MODEL) --no-rag

# Analyze all examples
analyze-examples: analyze-lending analyze-reentrancy analyze-multi
	@echo "✓ All example contracts analyzed"

# Run Foundry tests
test-foundry:
	@echo "Running Foundry tests..."
	cd exploit && forge test

# Run Foundry tests with verbose output
test-foundry-verbose:
	@echo "Running Foundry tests (verbose)..."
	cd exploit && forge test -vvv

# Run specific PoC test
test-poc:
	@if [ -z "$(POC)" ]; then \
		echo "Error: POC parameter is required"; \
		echo "Usage: make test-poc POC=PoC_Reentrancy_20240101_120000.sol"; \
		exit 1; \
	fi
	@echo "Running PoC test: $(POC)..."
	cd exploit && forge test --match-path src/test/$(POC) -vvv

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	rm -f analysis_report_*.md
	rm -f performance_metrics_*.json
	rm -f *.json
	rm -rf uploads/
	@echo "✓ Cleaned"

# Clean all including exploit tests
clean-all: clean
	@echo "Cleaning exploit tests..."
	rm -f exploit/src/test/PoC_*.sol
	rm -f exploit/src/test/basetest.sol
	cd exploit && forge clean
	@echo "✓ Deep clean complete"

# Initialize Foundry in exploit directory
init-foundry:
	@echo "Initializing Foundry in exploit directory..."
	cd exploit && forge init --no-git
	cd exploit && git submodule update --init --recursive
	@echo "✓ Foundry initialized"

# Show environment status
status:
	@echo "=== Environment Status ==="
	@echo "Python version:"
	@$(PYTHON) --version
	@echo ""
	@echo "Solidity version:"
	@$(VENV)/bin/solc --version 2>/dev/null || echo "Not installed (run: make install-solc)"
	@echo ""
	@echo "Foundry version:"
	@forge --version 2>/dev/null || echo "Not installed"
	@echo ""
	@echo "API Keys configured:"
	@[ -f .env ] && (grep -q "OPENAI_API_KEY" .env && echo "  ✓ OpenAI" || echo "  ✗ OpenAI") || echo "  .env not found"
	@[ -f .env ] && (grep -q "ANTHROPIC_API_KEY" .env && echo "  ✓ Anthropic" || echo "  ✗ Anthropic") || echo "  .env not found"
	@[ -f .env ] && (grep -q "GOOGLE_API_KEY" .env && echo "  ✓ Google Gemini" || echo "  ✗ Google Gemini") || echo "  .env not found"

# ===== Audit Contest Targets =====

# Analyze Hybra Finance contest contracts (Code4rena)
audit-hybra:
	@echo "Starting Hybra Finance audit analysis..."
	@bash analyze_hybra.sh

# Analyze single contract from Hybra Finance
audit-hybra-single:
	@if [ -z "$(CONTRACT)" ]; then \
		echo "Error: CONTRACT parameter is required"; \
		echo "Usage: make audit-hybra-single CONTRACT=GaugeV2"; \
		echo "Available contracts: GaugeManager, GaugeV2, MinterUpgradeable, VoterV3, VotingEscrow, GovernanceHYBR, HYBR, RewardHYBR, HybrSwapper, GaugeCL, GaugeFactoryCL, CLFactory, CLPool, DynamicSwapFeeModule"; \
		exit 1; \
	fi
	@echo "Analyzing Hybra $(CONTRACT)..."
	@mkdir -p audit_results/hybra_finance_single
	@$(PYTHON) main.py \
		--contract "contests/hybra-finance/ve33/contracts/$(CONTRACT).sol" \
		--all-models "$(MODEL)" \
		--no-rag \
		--export-md \
		--export-json "audit_results/hybra_finance_single/$(CONTRACT)_results.json" \
		|| $(PYTHON) main.py \
		--contract "contests/hybra-finance/cl/contracts/core/$(CONTRACT).sol" \
		--all-models "$(MODEL)" \
		--no-rag \
		--export-md \
		--export-json "audit_results/hybra_finance_single/$(CONTRACT)_results.json"

# Analyze entire ve33 contracts directory
audit-hybra-ve33:
	@echo "Analyzing Hybra ve33 contracts directory..."
	@mkdir -p audit_results/hybra_finance_ve33
	@$(PYTHON) main.py \
		--contract contests/hybra-finance/ve33/contracts/ \
		--all-models "$(MODEL)" \
		--no-rag \
		--export-md \
		--export-json "audit_results/hybra_finance_ve33/ve33_results.json"

# Analyze CL (concentrated liquidity) contracts
audit-hybra-cl:
	@echo "Analyzing Hybra CL contracts..."
	@mkdir -p audit_results/hybra_finance_cl
	@$(PYTHON) main.py \
		--contract contests/hybra-finance/cl/contracts/core/CLPool.sol \
		--all-models "$(MODEL)" \
		--no-rag \
		--export-md \
		--export-json "audit_results/hybra_finance_cl/CLPool_results.json"
	@$(PYTHON) main.py \
		--contract contests/hybra-finance/cl/contracts/core/CLFactory.sol \
		--all-models "$(MODEL)" \
		--no-rag \
		--export-md \
		--export-json "audit_results/hybra_finance_cl/CLFactory_results.json"
	@$(PYTHON) main.py \
		--contract contests/hybra-finance/cl/contracts/core/fees/DynamicSwapFeeModule.sol \
		--all-models "$(MODEL)" \
		--no-rag \
		--export-md \
		--export-json "audit_results/hybra_finance_cl/DynamicSwapFeeModule_results.json"

# Show Hybra audit results summary
audit-hybra-results:
	@echo "=== Hybra Finance Audit Results ==="
	@find audit_results -name "SUMMARY.md" -exec cat {} \;
	@echo ""
	@echo "All results available in: audit_results/"
