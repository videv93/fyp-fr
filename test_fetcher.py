# Test script to analyze contract fetching
import os
import sys
from utils.source_code_fetcher import fetch_and_flatten_contract

# Test with the provided contract address on Arbitrum
CONTRACT_ADDRESS = '0x62cf82fb0484af382714cd09296260edc1dc0c6c'
NETWORK = 'arbitrum'

# Output paths
output_path = os.path.join(
    os.path.dirname(__file__), "static_analysis", "test_contracts", f"{CONTRACT_ADDRESS}.sol"
)

print(f"Fetching contract {CONTRACT_ADDRESS} on {NETWORK}...")
print(f"Output will be saved to {output_path}")

try:
    # Fetch and save both flattened and separate contract files
    contract_files = fetch_and_flatten_contract(
        NETWORK,
        CONTRACT_ADDRESS,
        output_file=output_path,
        save_separate=True
    )
    
    print(f"\nFetched contracts successfully!")
    print(f"Flattened file: {output_path}")
    print(f"\nSeparate contract files ({len(contract_files)}):")
    for source_path, local_path in contract_files.items():
        print(f"  {source_path} -> {local_path}")
        
    # Check if contract folder exists and count .sol files
    contracts_dir = f"{os.path.splitext(output_path)[0]}_contracts"
    if os.path.exists(contracts_dir):
        sol_files = []
        for root, _, files in os.walk(contracts_dir):
            sol_files.extend([os.path.join(root, f) for f in files if f.endswith('.sol')])
        print(f"\nFound {len(sol_files)} .sol files in {contracts_dir}")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
