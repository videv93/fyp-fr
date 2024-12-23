import os
import yaml
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

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

    @classmethod
    def from_rule(cls, rule: Dict) -> 'VulnerabilityDoc':
        """Factory method to create VulnerabilityDoc from rule dict"""
        output = rule.get('output', {})

        return cls(
            name=rule.get('name', 'Unnamed Vulnerability'),
            description=output.get('description', ''),
            scenario=_extract_scenario(rule),
            property=_extract_property(rule),
            impact=_extract_impact(rule),
            code_patterns=_extract_code_patterns(rule),
            prevention=[output.get('recommendation', '')],
            exploit_template=_create_exploit_template(rule)
        )

def _extract_scenario(rule: Dict) -> str:
    """Extract scenario from rule properties"""
    properties = rule.get('property', [])
    return properties[0] if properties else ''

def _extract_property(rule: Dict) -> str:
    """Extract and join properties"""
    properties = rule.get('property', [])
    return ', '.join(properties) if properties else ''

def _extract_impact(rule: Dict) -> str:
    """Extract impact information"""
    impact = rule.get('impact', '')
    if not impact:
        impact = "Potential security vulnerability based on defined patterns"
    return impact

def _extract_code_patterns(rule: Dict) -> List[str]:
    """Extract and format code patterns from various rule sections"""
    patterns = []

    # Extract from functions
    functions = rule.get('functions', [])
    if functions:
        patterns.extend(_format_pattern_list(functions, "Functions to check:"))

    # Extract from contain rules
    contain_patterns = rule.get('function_contain_any', [])
    if contain_patterns:
        patterns.extend(_format_pattern_list(contain_patterns, "Must contain:"))

    # Extract from not contain rules
    not_contain = rule.get('function_not_contain_any', [])
    if not_contain:
        patterns.extend(_format_pattern_list(not_contain, "Must not contain:"))

    return patterns

def _format_pattern_list(patterns: List, prefix: str) -> List[str]:
    """Helper to format pattern lists with prefix"""
    formatted = [prefix]
    for pattern in patterns:
        if isinstance(pattern, list):
            formatted.extend([f"- {p}" for p in pattern])
        else:
            formatted.append(f"- {pattern}")
    return formatted

def _create_exploit_template(rule: Dict) -> Dict[str, str]:
    """Create exploit template from rule"""
    return {
        "setup": rule.get('exploit_setup', 'Setup steps not defined'),
        "execution": rule.get('exploit_execution', 'Execution steps not defined'),
        "validation": rule.get('exploit_validation', 'Validation steps not defined')
    }

def load_vulnerabilities_from_yaml(rules_dir: str) -> List[VulnerabilityDoc]:
    """Load vulnerability rules from YAML files with error handling"""
    vulnerabilities = []
    rules_path = Path(rules_dir)

    if not rules_path.exists():
        logger.error(f"Rules directory not found: {rules_dir}")
        return []

    for file_path in rules_path.glob('*.y*ml'):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                rule = yaml.safe_load(file)

                # Validate required fields
                if not isinstance(rule, dict):
                    logger.error(f"Invalid YAML format in {file_path}")
                    continue

                if 'name' not in rule:
                    logger.warning(f"Rule missing name in {file_path}")
                    continue

                vulnerability = VulnerabilityDoc.from_rule(rule)
                vulnerabilities.append(vulnerability)
                logger.info(f"Loaded vulnerability rule: {vulnerability.name}")

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing {file_path}: {e}")

    logger.info(f"Loaded {len(vulnerabilities)} vulnerability rules")
    return vulnerabilities

# Initialize vulnerability docs
try:
    VULNERABILITY_DOCS = load_vulnerabilities_from_yaml(
        os.path.join(os.path.dirname(__file__), '..', 'rules')
    )
except Exception as e:
    logger.error(f"Failed to load vulnerability rules: {e}")
    VULNERABILITY_DOCS = []
