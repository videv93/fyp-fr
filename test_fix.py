#!/usr/bin/env python3
# Simple test script to verify code snippet attachment fix without using slither

import json
from pathlib import Path

def test_snippets_extraction():
    # Mock function details (simplified)
    function_details = [
        {
            "contract": "TrustlessDonation",
            "function": "donate",
            "visibility": "external",
            "parameters": [("uint256", "amount")],
            "returns": [],
            "content": """function donate(uint256 amount) external {
        require(_donationToken.transferFrom(msg.sender, address(this), amount), "Donation failed");
        
        uint256 tokenId = _donationNFT.mintDonationNFT(msg.sender, amount);

        totalDonations += amount;
        
        emit Donation(msg.sender, address(this), amount, tokenId);
    }"""
        },
        {
            "contract": "TrustlessDonation",
            "function": "purchase",
            "visibility": "external",
            "parameters": [("address", "supplier"), ("uint256", "amount")],
            "returns": [],
            "content": """function purchase(address supplier, uint256 amount) external onlyCharityOwner {
        require(suppliers[supplier], "Invalid supplier");
        
        require(_donationToken.transfer(supplier, amount), "Purchase failed");

        totalDonations -= amount;

        emit Purchase(msg.sender, supplier, amount);
    }"""
        },
        {
            "contract": "DonationNFT",
            "function": "setCharityFactory",
            "visibility": "public",
            "parameters": [("address", "charityFactory")],
            "returns": [],
            "content": """function setCharityFactory(address charityFactory) public onlyOwner {
        charityFactoryAddress = charityFactory;
    }"""
        },
        {
            "contract": "TrustlessDonation",
            "function": "constructor",
            "visibility": "public",
            "parameters": [
                ("DonationToken", "donationToken"),
                ("DonationNFT", "donationNFT"),
                ("address", "_charityOwner"),
                ("string memory", "_charityName")
            ],
            "returns": [],
            "content": """constructor(DonationToken donationToken, DonationNFT donationNFT, address _charityOwner, string memory _charityName) {
        _donationToken = donationToken;
        _donationNFT = donationNFT;
        charityOwner = _charityOwner;
        charityName = _charityName;
    }"""
        }
    ]
    
    # Read contract source
    filepath = "static_analysis/test_contracts/sample.sol"
    with open(filepath, "r", encoding="utf-8") as f:
        source_code = f.read()
        
    # Create simplified data structure
    contract_info = {
        "function_details": function_details,
        "source_code": source_code,
    }
    
    # Create simplified vulnerabilities list
    vuln1 = {
        "vulnerability_type": "reentrancy",
        "affected_functions": ["donate", "purchase"]
    }
    
    vuln2 = {
        "vulnerability_type": "front_running",
        "affected_functions": ["DonationToken.approve"] 
    }
    
    vuln3 = {
        "vulnerability_type": "access_control",
        "affected_functions": ["setCharityFactory", "TrustlessDonation.constructor"]
    }
    
    vulnerabilities = [vuln1, vuln2, vuln3]
    
    # Mock the _attach_code_snippets functionality
    fn_map = {}
    for fn_detail in contract_info.get("function_details", []):
        function_name = fn_detail["function"]
        content = fn_detail.get("content")
        if content:  # Only add if content is not None or empty
            fn_map[function_name] = content
        # Handle fully qualified function names with contract prefixes
        qualified_name = f"{fn_detail['contract']}.{function_name}"
        if content:
            fn_map[qualified_name] = content
    
    # Debug: Print the function map
    print(f"\nDEBUG: Function map has {len(fn_map)} entries")
    for k, v in list(fn_map.items())[:5]:  # Show first 5 for brevity
        print(f"  - {k}: {v[:30]}..." if v else f"  - {k}: None")
    
    # Test each vulnerability
    for vuln in vulnerabilities:
        snippet_list = []
        affected_fns = vuln.get("affected_functions", [])
        print(f"\nDEBUG: Looking for code for {affected_fns}")
        
        for fn_name in affected_fns:
            if code_snip := fn_map.get(fn_name):
                print(f"  - Found direct match for {fn_name}")
                snippet_list.append(code_snip)
        
        # Set the code snippet
        if snippet_list:
            vuln["code_snippet"] = "\n\n".join(snippet_list)
        else:
            # Try to search for relevant code from source code directly if no matches are found
            source_code = contract_info.get("source_code", "")
            if source_code and affected_fns:
                for fn_name in affected_fns:
                    # Extract function name without contract prefix
                    simple_fn_name = fn_name.split('.')[-1] if '.' in fn_name else fn_name
                    print(f"  - Searching for '{simple_fn_name}' in source code")
                    
                    # Find in source code directly - basic approach
                    lines = source_code.split('\n')
                    for i, line in enumerate(lines):
                        # Look for function declaration with the name
                        if f"function {simple_fn_name}" in line:
                            print(f"    Found declaration at line {i+1}")
                            # Found function declaration, extract surrounding content
                            start = max(0, i-1)
                            end = min(len(lines), i+15)  # Get ~15 lines of context
                            vuln["code_snippet"] = "\n".join(lines[start:end])
                            break
                    else:
                        continue  # Try next function name if this one wasn't found
                    break  # Exit if we found at least one function
                else:
                    # If no functions were found after searching all
                    print(f"  - No matching functions found in source")
                    vuln["code_snippet"] = "(No matching function code found)"
            else:
                vuln["code_snippet"] = "(No matching function code found)"
    
    # Print results
    print("\n=== RESULTS ===")
    for idx, v in enumerate(vulnerabilities, 1):
        print(f"\nVulnerability #{idx}: {v['vulnerability_type']}")
        print(f"Affected Functions: {', '.join(v.get('affected_functions', []))}")
        if code := v.get('code_snippet'):
            print("Code snippet:")
            # Only print first 5 lines
            snippet_lines = code.split('\n')
            preview = '\n'.join(snippet_lines[:5])
            print(f"{preview}...")
        else:
            print("No code snippet found")

if __name__ == "__main__":
    test_snippets_extraction()