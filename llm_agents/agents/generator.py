# llm_agents/agents/generator.py

import time
from typing import Dict, List
import os
from openai import OpenAI


class GeneratorAgent:
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    def generate(self, exploit_plan: Dict) -> List[Dict]:
        """
        Generate a sequence of transactions or steps based on the exploit plan.
        In future, we can do more advanced logic here.
        """
        return []

    def generate_poc_contract(
        self, vulnerability_info: Dict, exploit_plan: Dict
    ) -> str:
        """
        Creates a Forge-Std test contract based on your template,
        injecting placeholders from vulnerability_info and exploit_plan.

        Return the raw Solidity code as a string.
        """

        template = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;
/*

import "forge-std/Test.sol";
import "./interface.sol";



contract ContractTest is Test {
    // Insert required interfaces or addresses
    // Example:
    // IUSDC constant USDC = IUSDC(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    function setUp() public {{
        vm.createSelectFork("mainnet", 15460093);
        // label addresses if needed
    }}
    
    function testExploit() public {{
        // Implement the steps from exploit_plan
        // e.g. {exploit_plan}
    }}
}

*/
"""
        return template

    def save_poc_locally(self, poc_code: str, vuln_type: str) -> str:
        """
        Saves the PoC code to a .sol file named with the vulnerability type + timestamp.
        Returns the filepath.
        """
        ts = int(time.time())
        filename = f"poc_{vuln_type}_{ts}.sol"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(poc_code)
        return filename
