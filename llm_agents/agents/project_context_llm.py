# ==============================
# File: llm_agents/agents/project_context_llm.py
# ==============================
from typing import Dict, List, Tuple, Set, Optional
from pathlib import Path
import os
import re
import json
import logging
from openai import OpenAI
from utils.print_utils import create_progress_spinner
from utils.langsmith_tracing import trace_agent_call

logger = logging.getLogger(__name__)

class ProjectContextLLMAgent:
    """
    LLM-powered Agent responsible for autonomously analyzing a directory of Solidity contract files
    to extract inter-contract relationships and provide rich context for vulnerability analysis.
    Unlike the rule-based ProjectContextAgent, this agent uses LLM reasoning to:
    1. Identify important relationships between contracts
    2. Highlight potential security concerns in inter-contract interactions
    3. Provide contextual insights based on call graph analysis
    """
    
    def __init__(self, model_config=None):
        from ..config import ModelConfig
        
        self.model_config = model_config or ModelConfig()
        self.model_name = self.model_config.get_model("project_context") if hasattr(self.model_config, "get_model") else "gpt-4o"
        
        # Get provider info for the selected model
        if hasattr(self.model_config, "get_provider_info"):
            _, api_key_env, _ = self.model_config.get_provider_info(self.model_name)
            # Initialize OpenAI client with the correct settings
            self.client = OpenAI(
                api_key=os.getenv(api_key_env),
                **self.model_config.get_openai_args(self.model_name)
            )
        else:
            # Fallback to default OpenAI client
            self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            
        # Simple regex patterns for initial metadata extraction
        self.contract_pattern = re.compile(r'(?:contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{', re.MULTILINE)
        
        # Analysis status and tracking
        self.job_id = None
    
    def analyze_project(self, contracts_dir: str, call_graph: Optional[Dict] = None) -> Dict:
        """
        Autonomously analyzes a multi-contract project to identify security-relevant
        inter-contract relationships and key insights.
        
        Args:
            contracts_dir: Path to directory containing separate contract files
            call_graph: Optional call graph from Slither analysis to enhance context
            
        Returns:
            A dictionary containing context information and insights
        """
        logger.info("LLM analyzing project structure and relationships")
        logger.info("Exploring contract directory...")
        
        contract_files = self._get_contract_files(contracts_dir)
        logger.info(f"Found {len(contract_files)} contract files")
        
        if hasattr(self, 'job_id') and self.job_id and 'socketio' in globals():
            try:
                socketio = globals()['socketio']
                socketio.emit('agent_status', {
                    'job_id': self.job_id,
                    'agent': 'project_context_llm',
                    'status': 'Processing contracts',
                    'detail': f"Found {len(contract_files)} contracts to analyze"
                })
            except Exception as e:
                logger.debug(f"Could not emit socketio update: {str(e)}")
        
        contract_metadata = self._extract_basic_metadata(contract_files)
        logger.info("Analyzing contract relationships")
        
        context = self._analyze_with_llm(contract_metadata, call_graph, contracts_dir)
        logger.info("LLM contract analysis complete")
        
        return context
    
    def _get_contract_files(self, contracts_dir: str) -> List[str]:
        contract_files = []
        for root, _, files in os.walk(contracts_dir):
            for file in files:
                if file.endswith('.sol'):
                    contract_files.append(os.path.join(root, file))
        return contract_files
    
    def _extract_basic_metadata(self, contract_files: List[str]) -> List[Dict]:
        metadata = []
        for file_path in contract_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                contract_names = []
                for match in self.contract_pattern.finditer(content):
                    contract_names.append(match.group(1))
                summary_lines = content.split('\n')[:15]
                summary = '\n'.join(summary_lines) + '\n...' if len(summary_lines) > 15 else content
                metadata.append({
                    'file_path': file_path,
                    'contract_names': contract_names,
                    'summary': summary,
                    'size': len(content)
                })
            except Exception as e:
                logger.error(f"Error extracting metadata from {file_path}: {str(e)}")
        return metadata
    
    def _analyze_with_llm(self, contract_metadata: List[Dict], call_graph: Optional[Dict], contracts_dir: str) -> Dict:
        """
        Use the LLM to analyze the project context, focusing on security-relevant relationships.
        """
        # Improved system prompt with explicit JSON output instructions for easier parsing.
        system_prompt = (
            "You are a smart contract security expert tasked with analyzing a multi-contract project. "
            "Your goal is to identify security-relevant relationships and interactions between contracts, "
            "including potential vulnerabilities arising from inter-contract calls, inheritance, permissions, and data flows.\n\n"
            "Return your analysis strictly as a JSON object with exactly the following keys (do not include any additional text):\n"
            "  - 'insights': a list of high-level security insights (strings) about the project.\n"
            "  - 'dependencies': a list of strings describing inter-contract relationships (e.g., 'ContractA calls ContractB').\n"
            "  - 'vulnerabilities': a list of potential vulnerability issues (strings) related to inter-contract interactions.\n"
            "  - 'important_functions': a list of critical function names (with contract prefixes if applicable) involved in inter-contract interactions.\n"
            "  - 'recommendations': a list of security recommendations (strings) for improving contract interactions.\n"
            "  - 'mermaid_diagram': a string containing a Mermaid diagram in 'graph TD' notation representing the contract relationships.\n\n"
            "Do not include any explanation or commentary outside of this JSON structure.\n\n"
            "Now, analyze the provided contract metadata and call graph, and output your analysis in the required JSON format."
        )
        
        user_prompt = f"I'm analyzing a multi-contract project with {len(contract_metadata)} contracts in directory: {contracts_dir}\n\n"
        user_prompt += "## Contract Files and Names\n"
        for meta in contract_metadata:
            user_prompt += f"File: {os.path.basename(meta['file_path'])}\n"
            user_prompt += f"Contracts: {', '.join(meta['contract_names'])}\n"
            user_prompt += "---\n"
        if call_graph:
            user_prompt += "\n## Call Graph (from Slither analysis)\n"
            user_prompt += json.dumps(call_graph, indent=2)
        
        response = self._call_llm(system_prompt, user_prompt)
        
        try:
            insights = self._extract_insights_from_response(response)
            dependencies = insights.get('dependencies', [])
            vulnerabilities = insights.get('vulnerabilities', [])
            general_insights = insights.get('insights', [])
            recommendations = insights.get('recommendations', [])
            important_functions = insights.get('important_functions', [])
            mermaid_diagram = insights.get('mermaid_diagram', '')
            
            total_relationships = len(dependencies) + len(important_functions)
            
            contract_info = []
            for meta in contract_metadata:
                for contract_name in meta.get('contract_names', []):
                    contract_info.append({
                        'file': os.path.basename(meta.get('file_path', 'unknown')),
                        'name': contract_name
                    })
            
            result = {
                'llm_analysis': response,
                'insights': general_insights,
                'dependencies': dependencies,
                'vulnerabilities': vulnerabilities,
                'recommendations': recommendations,
                'important_functions': important_functions,
                'contract_files': [m.get('file_path', 'unknown') for m in contract_metadata],
                'contract_details': contract_info,
                'call_graph': call_graph,
                'mermaid_diagram': mermaid_diagram,
                'stats': {
                    'total_contracts': len(contract_metadata),
                    'total_relationships': total_relationships,
                    'total_vulnerabilities': len(vulnerabilities),
                    'total_recommendations': len(recommendations),
                    'has_inter_contract_calls': total_relationships > 0
                }
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing LLM response: {str(e)}")
            return {
                'llm_analysis': response,
                'stats': {
                    'total_contracts': len(contract_metadata),
                    'total_relationships': 0,
                    'has_inter_contract_calls': False
                }
            }
    
    @trace_agent_call("project_context")
    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        # Import token tracker
        from utils.token_tracker import token_tracker
        
        if not self.model_config.supports_reasoning(self.model_name):
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        else:
            messages = [
                {"role": "user", "content": system_prompt + "\n\n" + user_prompt}
            ]
        if self.model_name == "claude-3-7-sonnet-latest":
            resp = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                max_tokens=64000,
                extra_body={ "thinking": { "type": "enabled", "budget_tokens": 2000 } },
            )
        else:
            resp = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages
            )
        
        # Track token usage
        if hasattr(resp, 'usage') and resp.usage:
            token_tracker.log_tokens(
                agent_name="project_context",
                model_name=self.model_name,
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                total_tokens=resp.usage.total_tokens
            )
        
        return resp.choices[0].message.content.strip()
    
    def _extract_insights_from_response(self, response: str) -> Dict:
        result = {
            'insights': [],
            'dependencies': [],
            'vulnerabilities': [],
            'important_functions': [],
            'recommendations': [],
            'mermaid_diagram': ''
        }
        
        # First try to parse the response as JSON (from newer JSON-formatted responses)
        try:
            # Find JSON content - handle both pure JSON responses and JSON embedded in text
            json_pattern = re.compile(r'\{[\s\S]*\}')
            json_match = json_pattern.search(response)
            
            if json_match:
                json_str = json_match.group(0)
                try:
                    # Parse the JSON content
                    parsed_json = json.loads(json_str)
                    
                    # Extract fields from parsed JSON
                    if 'insights' in parsed_json and isinstance(parsed_json['insights'], list):
                        result['insights'] = parsed_json['insights']
                    if 'dependencies' in parsed_json and isinstance(parsed_json['dependencies'], list):
                        result['dependencies'] = parsed_json['dependencies']
                    if 'vulnerabilities' in parsed_json and isinstance(parsed_json['vulnerabilities'], list):
                        result['vulnerabilities'] = parsed_json['vulnerabilities']
                    if 'important_functions' in parsed_json and isinstance(parsed_json['important_functions'], list):
                        result['important_functions'] = parsed_json['important_functions']
                    if 'recommendations' in parsed_json and isinstance(parsed_json['recommendations'], list):
                        result['recommendations'] = parsed_json['recommendations']
                    if 'mermaid_diagram' in parsed_json and isinstance(parsed_json['mermaid_diagram'], str):
                        result['mermaid_diagram'] = parsed_json['mermaid_diagram']
                        
                    # If we successfully parsed the JSON and found at least one category, return early
                    if any(len(result.get(key, [])) > 0 for key in result.keys() if key != 'mermaid_diagram') or result.get('mermaid_diagram'):
                        return result
                except json.JSONDecodeError:
                    # If JSON parsing fails, fall back to regex extraction
                    pass
        except Exception as e:
            logger.error(f"Error parsing JSON response: {str(e)}")
            # Continue with regex extraction as fallback
            
        # Fallback to regex extraction for markdown-formatted responses
        mermaid_pattern = re.compile(r'```mermaid\s*\n(.*?)\n\s*```', re.DOTALL)
        diagram_match = mermaid_pattern.search(response)
        if diagram_match:
            result['mermaid_diagram'] = diagram_match.group(1).strip()
        
        sections = self._parse_sections(response)
        for section_title, section_content in sections.items():
            title_lower = section_title.lower()
            if any(term in title_lower for term in ['relationship', 'dependencies', 'interaction']):
                items = self._extract_list_items(section_content)
                if items:
                    result['dependencies'].extend(items)
            elif any(term in title_lower for term in ['security', 'vulnerability', 'risk']):
                items = self._extract_list_items(section_content)
                if items:
                    result['vulnerabilities'].extend(items)
            elif any(term in title_lower for term in ['key function', 'important function', 'critical function']):
                items = self._extract_list_items(section_content)
                if items:
                    result['important_functions'].extend(items)
            elif any(term in title_lower for term in ['recommend', 'suggest', 'mitigate']):
                items = self._extract_list_items(section_content)
                if items:
                    result['recommendations'].extend(items)
            elif any(term in title_lower for term in ['insight', 'finding', 'observation', 'summary']):
                items = self._extract_list_items(section_content)
                if items:
                    result['insights'].extend(items)
        
        if not any(len(items) > 0 for items in result.values()):
            all_items = self._extract_list_items(response)
            for item in all_items:
                item_lower = item.lower()
                if any(term in item_lower for term in ['interact', 'call', 'inherit', 'relationship']):
                    result['dependencies'].append(item)
                elif any(term in item_lower for term in ['vulnerab', 'risk', 'issue', 'attack', 'exploit']):
                    result['vulnerabilities'].append(item)
                elif any(term in item_lower for term in ['function', 'method']):
                    result['important_functions'].append(item)
                elif any(term in item_lower for term in ['recommend', 'should', 'suggest', 'mitigate']):
                    result['recommendations'].append(item)
                else:
                    result['insights'].append(item)
        
        if sum(len(items) for items in result.values()) == 0:
            result['insights'] = ["The LLM analysis did not yield clear structured insights. Manual review recommended."]
        
        return result
    
    def _parse_sections(self, text: str) -> Dict[str, str]:
        sections = {}
        lines = text.split('\n')
        current_section = "General"
        current_content = []
        for line in lines:
            stripped_line = line.strip()
            is_header = False
            if stripped_line and (stripped_line.endswith(':') or 
                                 stripped_line.isupper() or 
                                 stripped_line.startswith('#') or
                                 (len(stripped_line) <= 100 and stripped_line.split()[0].endswith('.'))):
                is_header = True
            if is_header:
                if current_content:
                    sections[current_section] = '\n'.join(current_content)
                current_section = stripped_line.strip('#:-. ').strip()
                current_content = []
            else:
                if stripped_line:
                    current_content.append(stripped_line)
        if current_content:
            sections[current_section] = '\n'.join(current_content)
        return sections
    
    def _extract_list_items(self, text: str) -> List[str]:
        items = []
        lines = text.split('\n')
        for line in lines:
            stripped = line.strip()
            if (stripped.startswith('-') or 
                stripped.startswith('*') or 
                (len(stripped) > 2 and stripped[0].isdigit() and stripped[1] in ['.',')']) or
                (len(stripped) > 3 and stripped[:2].isdigit() and stripped[2] in ['.',')'])):
                item = stripped
                if item.startswith('-') or item.startswith('*'):
                    item = item[1:]
                elif item[0].isdigit() and item[1] in ['.',')']:
                    item = item[2:]
                elif item[:2].isdigit() and item[2] in ['.',')']:
                    item = item[3:]
                items.append(item.strip())
            elif stripped and items:
                items[-1] += ' ' + stripped
        return items
    
    def generate_prompt_section(self, analysis_result: Dict) -> str:
        if not analysis_result:
            return "=== INTER-CONTRACT RELATIONSHIPS AND SECURITY ANALYSIS ===\nNo inter-contract relationships found."
        
        stats = analysis_result.get('stats', {})
        insights = analysis_result.get('insights', [])
        dependencies = analysis_result.get('dependencies', [])
        vulnerabilities = analysis_result.get('vulnerabilities', [])
        recommendations = analysis_result.get('recommendations', [])
        important_functions = analysis_result.get('important_functions', [])
        contract_files = analysis_result.get('contract_files', [])
        call_graph = analysis_result.get('call_graph', [])
        section = "=== INTER-CONTRACT RELATIONSHIPS AND SECURITY ANALYSIS ===\n"
        section += f"Analyzed {stats.get('total_contracts', 0)} contracts.\n"
        if contract_files:
            section += "Contracts: " + ", ".join(contract_files[:5])
            if len(contract_files) > 5:
                section += f" and {len(contract_files) - 5} more"
            section += "\n\n"
        if insights:
            section += "Key Insights:\n"
            for insight in insights:
                section += f"- {insight}\n"
            section += "\n"
        if dependencies:
            section += "Contract Dependencies:\n"
            for dep in dependencies:
                section += f"- {dep}\n"
            section += "\n"
        if important_functions:
            section += "Important Cross-Contract Functions:\n"
            for func in important_functions:
                section += f"- {func}\n"
            section += "\n"
        if vulnerabilities:
            section += "Potential Vulnerabilities in Contract Interactions:\n"
            for vuln in vulnerabilities:
                section += f"- {vuln}\n"
            section += "\n"
        if recommendations:
            section += "Security Recommendations:\n"
            for rec in recommendations:
                section += f"- {rec}\n"
            section += "\n"
        if call_graph:
            section += "Call Graph:\n"
            for call in call_graph:
                section += f"- {call}\n"
            section += "\n"
        if not any([insights, dependencies, vulnerabilities, recommendations, important_functions]):
            section += "Raw LLM Analysis:\n"
            section += analysis_result.get('llm_analysis', "Analysis unavailable")
        return section
