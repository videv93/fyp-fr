# rag/knowledge_base.py

import os
import yaml
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class VulnerabilityDoc:
    name: str
    description: str
    scenario: str
    property: str
    impact: str
    code_patterns: List[str]
    prevention: List[str]
    exploit_template: Dict[str, str]

# Enhanced parsing with better mapping
def load_vulnerabilities_from_yaml(rules_dir: str) -> List[VulnerabilityDoc]:
    vulnerabilities = []
    for filename in os.listdir(rules_dir):
        if filename.endswith('.yml') or filename.endswith('.yaml'):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, 'r') as file:
                rule = yaml.safe_load(file)
                name = rule.get('name', 'Unnamed Vulnerability')
                output = rule.get('output', {})
                title = output.get('title', '')
                description = output.get('description', '')
                recommendation = output.get('recommendation', '')

                # Extract code patterns from function_contain_any and function_not_contain_any
                contain_any = rule.get('function_contain_any', [])
                not_contain_any = rule.get('function_not_contain_any', [])
                code_patterns = []
                for pattern in contain_any:
                    if isinstance(pattern, list):
                        code_patterns.extend(pattern)
                    else:
                        code_patterns.append(pattern)
                for pattern in not_contain_any:
                    if isinstance(pattern, list):
                        code_patterns.extend(pattern)
                    else:
                        code_patterns.append(pattern)

                # Extract scenario and property
                properties = rule.get('property', [])
                scenario = properties[0] if properties else ''
                property_desc = ', '.join(properties)

                # Impact can be derived or defined separately
                impact = "Potential exploitation based on the defined vulnerability."

                # Define exploit_template based on static analysis prompts or predefined templates
                exploit_template = {
                    "setup": "Derived from setup_steps in the exploit plan.",
                    "execution": "Derived from execution_steps in the exploit plan.",
                    "validation": "Derived from validation_steps in the exploit plan."
                }

                vulnerability = VulnerabilityDoc(
                    name=name,
                    description=description,
                    scenario=scenario,
                    property=property_desc,
                    impact=impact,
                    code_patterns=code_patterns,
                    prevention=[recommendation],
                    exploit_template=exploit_template
                )
                vulnerabilities.append(vulnerability)
    return vulnerabilities


VULNERABILITY_DOCS = load_vulnerabilities_from_yaml(os.path.join(os.path.dirname(__file__), '..', 'rules'))
