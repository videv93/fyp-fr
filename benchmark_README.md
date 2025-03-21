# Smart Contract Vulnerability Benchmark Evaluator

This tool evaluates the performance of vulnerability detection reports against ground truth synopsis files. It supports both LLM-based and string matching evaluation methods, and can process multiple report configurations in parallel.

## Features

- **LLM-Based Evaluation**: Uses a sophisticated LLM (default: Claude 3.7 Sonnet) to compare report content against ground truth
- **String Matching Fallback**: Provides a simple string matching method when LLM evaluation fails or is disabled
- **Special Handling for No-Error Contracts**: Properly evaluates reports for contracts that have no vulnerabilities
- **Parallel Processing**: Efficiently processes multiple reports using asynchronous operations
- **Comprehensive Metrics**: Calculates precision, recall, F1 score, and more
- **Visualization Generation**: Creates plots for metrics comparison, confusion matrices, and F1 scores by category

## Directory Structure

The evaluator works with the following directory structure:

```
/
├── benchmark_data/             # Contains benchmark data with vulnerabilities
│   ├── contracts/              # Vulnerable contracts
│   ├── reports/                # Reports from various tools
│   └── synopsis/               # Ground truth descriptions
├── benchmark_data_no_errors/   # Contains benchmark data without vulnerabilities
│   └── contracts/
├── benchmark_results/          # Output directory for evaluation results
└── uploads/                    # Contains directories with reports to evaluate
    ├── claude-all/             # Model configuration #1
    ├── o3-mini-rag/            # Model configuration #2
    └── ...
```

## Usage

### Basic Usage

```bash
python benchmark_evaluator.py
```

This will evaluate all report directories in the `uploads/` folder against ground truth synopsis files.

### Specific Report Directories

```bash
python benchmark_evaluator.py --report-dirs o3-mini-rag claude-all
```

This evaluates only the specified report directories.

### Disable LLM Evaluation

```bash
python benchmark_evaluator.py --no-llm
```

This uses only string matching evaluation.

### Change Evaluation Model

```bash
python benchmark_evaluator.py --eval-model o3-mini
```

This uses the specified model for evaluation instead of the default.

### Custom Directories

```bash
python benchmark_evaluator.py --uploads-dir custom/uploads --results-dir custom/results
```

This changes the location of uploads and results directories.

## Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--uploads-dir` | Directory containing generated reports | `uploads` |
| `--benchmark-data-dir` | Directory containing benchmark data with errors | `benchmark_data` |
| `--benchmark-no-errors-dir` | Directory containing benchmark data with no errors | `benchmark_data_no_errors` |
| `--results-dir` | Directory to save evaluation results | `benchmark_results` |
| `--report-dirs` | Specific report directories to evaluate | All directories in uploads/ |
| `--use-llm` | Use LLM-based evaluation | True |
| `--no-llm` | Disable LLM-based evaluation | False |
| `--eval-model` | LLM model to use for evaluation | `claude-3-7-sonnet-latest` |
| `--max-workers` | Maximum number of parallel workers | 5 |

## Output

The evaluator generates:

1. **JSON Results File**: Contains detailed evaluation results for all reports
2. **Log File**: Provides information about the evaluation process
3. **Visualization Images**:
   - Metrics comparison (precision, recall, F1) by model configuration
   - Confusion matrices for each model configuration
   - F1 scores by vulnerability category

## Evaluation Metrics

- **Precision**: The fraction of correctly identified vulnerabilities among all reported vulnerabilities
- **Recall**: The fraction of actual vulnerabilities that are correctly identified
- **F1 Score**: Harmonic mean of precision and recall
- **Macro F1**: Average F1 score across all categories

## LLM Evaluation Process

When using LLM evaluation, the system:

1. Sends the synopsis (ground truth) and the report to the LLM
2. Asks the LLM to analyze whether the report covers the vulnerabilities in the synopsis
3. Has the LLM return counts of true positives, false positives, and false negatives
4. Calculates precision, recall, and F1 score based on these counts

If LLM evaluation fails after multiple attempts, the system falls back to string matching.

## String Matching Evaluation

The string matching method:

1. Extracts key security terms from the synopsis
2. Checks how many of these terms appear in the report
3. Counts security-related terms in the report that aren't in the synopsis as potential false positives
4. Calculates metrics based on these counts

## No-Errors Contract Evaluation

For contracts that have no vulnerabilities:

- If the report correctly identifies no vulnerabilities: 100% precision, recall, and F1 score
- If the report incorrectly identifies vulnerabilities: 0% precision, counted as false positives

## Requirements

- Python 3.8+
- OpenAI API key (for LLM evaluation)
- Required Python packages: pandas, numpy, matplotlib, seaborn, openai