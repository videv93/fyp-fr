from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import json
import threading
import time
import sys
import uuid
import re
import subprocess
from typing import Dict, Tuple, List, Optional

from httpx import main

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from main project
from utils.source_code_fetcher import fetch_and_flatten_contract
from static_analysis.parse_contract import analyze_contract
from llm_agents.agent_coordinator import AgentCoordinator
from llm_agents.config import ModelConfig
from llm_agents.agents.runner import ExploitRunner

app = Flask(__name__, static_folder='build')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store job states
jobs = {}

# Store uploaded contracts
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/upload-contract', methods=['POST'])
def upload_contract():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    job_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{file.filename}")
    file.save(file_path)

    jobs[job_id] = {
        'status': 'uploaded',
        'contract_path': file_path,
        'filename': file.filename
    }

    return jsonify({
        'job_id': job_id,
        'status': 'uploaded',
        'message': 'Contract uploaded successfully'
    })

@app.route('/api/fetch-contract', methods=['POST'])
def fetch_contract():
    data = request.json
    if not data or 'address' not in data or 'network' not in data:
        return jsonify({'error': 'Address and network are required'}), 400

    job_id = str(uuid.uuid4())
    output_file = os.path.join(UPLOAD_FOLDER, f"{job_id}_contract.sol")

    try:
        # Start fetching in a separate thread
        jobs[job_id] = {
            'status': 'fetching',
            'address': data['address'],
            'network': data['network']
        }

        threading.Thread(
            target=fetch_contract_thread,
            args=(job_id, data['network'], data['address'],output_file)
        ).start()

        return jsonify({
            'job_id': job_id,
            'status': 'fetching',
            'message': 'Contract fetching started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def fetch_contract_thread(job_id, network, address, output_file):
    try:
        fetch_and_flatten_contract(network, address, output_file)
        jobs[job_id].update({
            'status': 'fetched',
            'contract_path': output_file,
            'filename': f"{address}.sol"
        })
        socketio.emit('contract_fetched', {'job_id': job_id, 'status': 'fetched'})
    except Exception as e:
        jobs[job_id].update({
            'status': 'error',
            'error': str(e)
        })
        socketio.emit('contract_fetch_error', {'job_id': job_id, 'error': str(e)})

@app.route('/api/analyze', methods=['POST'])
def start_analysis():
    data = request.json
    if not data or 'job_id' not in data:
        return jsonify({'error': 'Job ID is required'}), 400

    job_id = data['job_id']
    if job_id not in jobs:
        return jsonify({'error': 'Job not found'}), 404

    job = jobs[job_id]
    if job['status'] not in ['uploaded', 'fetched']:
        return jsonify({'error': 'Contract not ready for analysis'}), 400

    # Get model configuration
    model_config = ModelConfig(
        analyzer_model=data.get('analyzer_model', 'o3-mini'),
        skeptic_model=data.get('skeptic_model', 'o3-mini'),
        exploiter_model=data.get('exploiter_model', 'o3-mini'),
        generator_model=data.get('generator_model', 'o3-mini'),
        skip_poc_generation=data.get('skip_poc_generation', False),
        export_markdown=data.get('export_markdown', False),
    )

    # Get auto-run configuration
    auto_run_config = {
        'auto_run': data.get('auto_run', True),
        'max_retries': data.get('max_retries', 3)
    }

    # Get RAG configuration
    use_rag = data.get('use_rag', True)

    # Update job status
    jobs[job_id].update({
        'status': 'analyzing',
        'model_config': {
            'analyzer_model': model_config.analyzer_model,
            'skeptic_model': model_config.skeptic_model,
            'exploiter_model': model_config.exploiter_model,
            'generator_model': model_config.generator_model,
            'skip_poc_generation': model_config.skip_poc_generation,
            'export_markdown': model_config.export_markdown,
        },
        'auto_run_config': auto_run_config,
        'use_rag': use_rag
    })

    # Start analysis in a separate thread
    threading.Thread(
        target=analyze_thread,
        args=(job_id, job['contract_path'], model_config, auto_run_config, use_rag)
    ).start()

    return jsonify({
        'job_id': job_id,
        'status': 'analyzing',
        'message': 'Analysis started'
    })

def analyze_thread(job_id, contract_path, model_config, auto_run_config, use_rag=True):
    try:
        # Emit analysis started event
        print(f"Emitting analysis_started event for job {job_id}")
        socketio.emit('analysis_started', {'job_id': job_id})

        # Static Analysis
        print(f"Emitting agent_active event for static_analyzer for job {job_id}")
        socketio.emit('agent_active', {
            'job_id': job_id,
            'agent': 'static_analyzer',
            'status': 'Starting static analysis',
            'detail': 'Parsing contract code and preparing for analysis'
        })

        # Emit status update for parsing
        socketio.emit('agent_status', {
            'job_id': job_id,
            'agent': 'static_analyzer',
            'status': 'Parsing contract',
            'detail': 'Extracting functions, call graph, and contract structure'
        })

        # Run static analysis
        # Add intermediate status updates during static analysis
        socketio.emit('agent_status', {
            'job_id': job_id,
            'agent': 'static_analyzer',
            'status': 'Running Slither',
            'detail': 'Executing static analysis tools to detect common vulnerabilities'
        })

        function_details, call_graph, detector_results = analyze_contract(contract_path)

        # Count the number of functions
        function_count = len(function_details) if function_details else 0

        # Get summary of detector results if available
        detector_count = 0
        if detector_results:
            try:
                # Try to count results from various detectors
                detector_count = sum(len(items) for _, items in detector_results.items() if isinstance(items, list))
            except:
                # Fallback: just indicate we have some results
                detector_count = 1 if detector_results else 0

        # Emit status with analysis summary
        socketio.emit('agent_status', {
            'job_id': job_id,
            'agent': 'static_analyzer',
            'status': 'Analysis complete',
            'detail': f'Found {function_count} functions and {detector_count} potential issues'
        })

        print(f"Emitting agent_complete event for static_analyzer for job {job_id}")
        socketio.emit('agent_complete', {
            'job_id': job_id,
            'agent': 'static_analyzer',
            'result': f'Analyzed {function_count} functions'
        })

        # Read contract source
        with open(contract_path, "r", encoding="utf-8") as f:
            source_code = f.read()

        # Prepare contract info
        contract_info = {
            "function_details": function_details,
            "call_graph": call_graph,
            "source_code": source_code,
            "detector_results": detector_results,
        }

        # Initialize agent coordinator using SocketIOAgentCoordinator to emit events
        coordinator = SocketIOAgentCoordinator(
            job_id,
            model_config=model_config,
            use_rag=use_rag
        )

        # Run analysis
        results = coordinator.analyze_contract(contract_info, auto_run_config=auto_run_config)

        # Update job status
        jobs[job_id].update({
            'status': 'completed',
            'results': results
        })

        # Emit analysis completed event
        print(f"Emitting analysis_complete event for job {job_id}")
        socketio.emit('analysis_complete', {
            'job_id': job_id,
            'status': 'completed',
            'vulnerabilities_count': len(results.get('rechecked_vulnerabilities', [])),
            'pocs_count': len(results.get('generated_pocs', []))
        })

    except Exception as e:
        print(f"Error in analysis: {str(e)}")
        jobs[job_id].update({
            'status': 'error',
            'error': str(e)
        })
        socketio.emit('analysis_error', {'job_id': job_id, 'error': str(e)})

@app.route('/api/status/<job_id>', methods=['GET'])
def get_status(job_id):
    if job_id not in jobs:
        return jsonify({'error': 'Job not found'}), 404

    return jsonify({
        'job_id': job_id,
        'status': jobs[job_id]['status']
    })

@app.route('/api/results/<job_id>', methods=['GET'])
def get_results(job_id):
    if job_id not in jobs:
        return jsonify({'error': 'Job not found'}), 404

    job = jobs[job_id]
    if job['status'] != 'completed':
        return jsonify({'error': 'Analysis not completed'}), 400

    return jsonify({
        'job_id': job_id,
        'status': 'completed',
        'results': job['results']
    })

# Custom SocketIO event handlers to provide real-time updates
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# Import the generator
from llm_agents.agents.generator import GeneratorAgent

# Modified version of GeneratorAgent for the frontend
class FrontendGeneratorAgent(GeneratorAgent):
    def generate(self, exploit_data):
        """Override parent generate method to use correct paths for frontend"""
        vuln_info = exploit_data.get("vulnerability", {})
        exploit_plan = exploit_data.get("exploit_plan", {})
        vuln_type = vuln_info.get("vulnerability_type", "unknown").replace(" ", "_")

        # Generate the PoC contract
        contract_code = self.generate_poc_contract(vuln_info, exploit_plan)

        # Save the contract to a file using our custom method - in the MAIN exploit directory
        filename = self.save_poc_locally(contract_code, vuln_type)

        # For the forge test command, we need to use just the relative path from within the exploit dir
        rel_path = filename.split("exploit/")[-1] if "exploit/" in filename else filename

        return {
            "exploit_code": contract_code,
            "exploit_file": filename,
            "execution_command": f"forge test -vv --match-path {rel_path}"
        }

    def save_poc_locally(self, poc_code: str, vuln_type: str) -> str:
        """
        Save the generated PoC contract to a file in the main exploit directory

        Args:
            poc_code: The Solidity code
            vuln_type: Type of vulnerability

        Returns:
            The filename where the code was saved
        """
        # Use the main exploit directory instead of frontend_poc/exploit
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_exploit_dir = os.path.join(project_root, "exploit")
        os.makedirs(os.path.join(main_exploit_dir, "src", "test"), exist_ok=True)

        ts = int(time.time())
        rel_filename = f"src/test/PoC_{vuln_type}_{ts}.sol"
        abs_filename = os.path.join(main_exploit_dir, rel_filename)

        with open(abs_filename, "w", encoding="utf-8") as f:
            f.write(poc_code)

        print(f"PoC saved to {abs_filename}")
        return abs_filename

    def generate_basetest_file(self) -> str:
        """Generate basetest.sol and save it to the main exploit/src/test/basetest.sol"""
        # Use the main exploit directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        main_exploit_dir = os.path.join(project_root, "exploit")
        print(main_exploit_dir)
        abs_filename = os.path.join(main_exploit_dir, "src", "test", "basetest.sol")

        # Check if basetest.sol already exists
        if os.path.exists(abs_filename):
            print(f"Base test file already exists at {abs_filename}")
            return abs_filename

        # Generate the basetest file content
        basetest_content = self._generate_basetest_content()

        # Save the file
        with open(abs_filename, "w", encoding="utf-8") as f:
            f.write(basetest_content)

        print(f"Created base test file at {abs_filename}")
        return abs_filename

# Modified version of ExploitRunner for the frontend
class FrontendExploitRunner(ExploitRunner):
    def _execute_test(self, command: str) -> Tuple[bool, str, str]:
        """
        Execute a Foundry test command and capture the output.
        Uses the main exploit directory.

        Args:
            command: Forge test command to execute

        Returns:
            Tuple of (success, output, error_message)
        """
        try:
            # Use main exploit directory as the working directory
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            main_exploit_dir = os.path.join(project_root, "exploit")
            print(main_exploit_dir)
            print(f"Executing test in directory: {main_exploit_dir}")

            # Execute the command
            result = subprocess.run(
                command,
                shell=True,
                cwd=main_exploit_dir,
                capture_output=True,
                text=True
            )

            # Get complete output
            output = result.stdout + "\n" + result.stderr

            # Check if the test passed
            if result.returncode == 0 and "FAIL" not in result.stdout:
                return True, output, ""

            # Extract error message
            error_pattern = r"(Error|Fail|Revert|Panic|Error:\s*.*|.*reverted.*)"
            error_matches = re.findall(error_pattern, output, re.IGNORECASE)
            error_message = "\n".join(error_matches) if error_matches else "Unknown error"

            return False, output, error_message

        except Exception as e:
            return False, "", f"Error executing test: {str(e)}"

# Modified version of AgentCoordinator that emits SocketIO events
class SocketIOAgentCoordinator(AgentCoordinator):
    def __init__(self, job_id, model_config=None, use_rag=True):
        super().__init__(model_config, use_rag=use_rag)
        self.job_id = job_id
        # Replace the default runner and generator with our custom frontend versions
        self.runner = FrontendExploitRunner(model_config=model_config)
        self.generator = FrontendGeneratorAgent(model_config=model_config)

    def analyze_contract(self, contract_info, auto_run_config=None):
        # Set default auto-run config if none provided
        if auto_run_config is None:
            auto_run_config = {"auto_run": True, "max_retries": 3}

        # Configure runner's max retries
        self.runner.max_retries = auto_run_config.get("max_retries", 3)

        # 1. Analyzer => all vulnerabilities
        print(f"Emitting agent_active event for analyzer for job {self.job_id}")
        socketio.emit('agent_active', {
            'job_id': self.job_id,
            'agent': 'analyzer',
            'status': 'Initializing vulnerability analysis',
            'detail': 'Loading contract code and preparing for analysis...'
        })

        # Emit status update before calling analyzer
        socketio.emit('agent_status', {
            'job_id': self.job_id,
            'agent': 'analyzer',
            'status': 'Analyzing contract code',
            'detail': f'Searching for potential vulnerabilities. Using RAG: {self.use_rag}'
        })

        # We need to capture the RAG details to emit them
        if self.use_rag:
            # Emit status update about RAG process starting
            socketio.emit('agent_status', {
                'job_id': self.job_id,
                'agent': 'analyzer',
                'status': 'Retrieving similar vulnerabilities',
                'detail': 'Searching knowledge base for relevant vulnerability patterns'
            })

            # Get the query text and retrieve relevant docs manually
            query_text = self.analyzer._build_query_text(contract_info)
            relevant_docs = self.analyzer.retriever.invoke(contract_info["source_code"])

            # Prepare RAG details to emit
            rag_details = []
            for i, doc in enumerate(relevant_docs, start=1):
                meta = doc.metadata
                filename = meta.get('filename', 'Unknown')
                lines_range = f"{meta.get('start_line', 0)} - {meta.get('end_line', 0)}"
                vuln_categories = meta.get("vuln_categories", [])
                content_preview = doc.page_content[:500] + "..." if len(doc.page_content) > 500 else doc.page_content

                rag_details.append({
                    'filename': filename,
                    'lines_range': lines_range,
                    'vuln_categories': vuln_categories,
                    'content_preview': content_preview
                })

            # Emit RAG details
            socketio.emit('rag_details', {
                'job_id': self.job_id,
                'details': rag_details
            })

            # Emit status update about RAG results
            socketio.emit('agent_status', {
                'job_id': self.job_id,
                'agent': 'analyzer',
                'status': 'Retrieved similar vulnerabilities',
                'detail': f'Found {len(relevant_docs)} similar vulnerability patterns to guide analysis'
            })

        # Run the analyzer
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])

        # Emit status with results summary
        socketio.emit('agent_status', {
            'job_id': self.job_id,
            'agent': 'analyzer',
            'status': 'Analysis complete',
            'detail': f'Found {len(vulnerabilities)} potential vulnerabilities to investigate'
        })

        print(f"Emitting agent_complete event for analyzer for job {self.job_id}")
        socketio.emit('agent_complete', {
            'job_id': self.job_id,
            'agent': 'analyzer',
            'result': f'Found {len(vulnerabilities)} potential vulnerabilities'
        })

        if not vulnerabilities:
            return {"status": "no_vulnerability_found"}

        # 2. Skeptic => re-check validity
        print(f"Emitting agent_active event for skeptic for job {self.job_id}")
        socketio.emit('agent_active', {
            'job_id': self.job_id,
            'agent': 'skeptic',
            'status': 'Initializing validity check',
            'detail': 'Preparing to verify the reported vulnerabilities...'
        })

        # Emit status update with number of vulnerabilities to check
        socketio.emit('agent_status', {
            'job_id': self.job_id,
            'agent': 'skeptic',
            'status': 'Validating findings',
            'detail': f'Checking validity of {len(vulnerabilities)} potential vulnerabilities'
        })

        # Run the skeptic
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"], vulnerabilities
        )

        # Count high confidence vulnerabilities - with float conversion for safety
        high_conf_count = len([v for v in rechecked_vulns if float(v.get("skeptic_confidence", 0)) > 0.5])

        # Emit status with results summary
        socketio.emit('agent_status', {
            'job_id': self.job_id,
            'agent': 'skeptic',
            'status': 'Validation complete',
            'detail': f'Found {high_conf_count} high-confidence vulnerabilities'
        })

        print(f"Emitting agent_complete event for skeptic for job {self.job_id}")
        socketio.emit('agent_complete', {
            'job_id': self.job_id,
            'agent': 'skeptic',
            'result': f'Confirmed {high_conf_count} vulnerabilities with high confidence'
        })

        # 3. Generate PoCs for high-confidence vulnerabilities
        generated_pocs = []

        # Generate for only one for now
        high_conf_vulns = [v for v in rechecked_vulns if float(v.get("skeptic_confidence", 0)) > 0.5]
        if high_conf_vulns:
            for i, vul in enumerate(high_conf_vulns):
                # EXPLOITER AGENT
                vuln_type = vul.get('vulnerability_type', 'Unknown')
                print(f"Emitting agent_active event for exploiter for job {self.job_id}")
                socketio.emit('agent_active', {
                    'job_id': self.job_id,
                    'agent': 'exploiter',
                    'status': 'Creating exploit plan',
                    'detail': f'Planning attack strategy for {vuln_type} vulnerability'
                })

                # Emit status update with vulnerability details
                socketio.emit('agent_status', {
                    'job_id': self.job_id,
                    'agent': 'exploiter',
                    'status': 'Analyzing vulnerability',
                    'detail': f'Determining required steps to demonstrate {vuln_type}'
                })

                # Run the exploiter
                plan_data = self.exploiter.generate_exploit_plan(vul)

                # Get step counts for details
                setup_steps = len(plan_data.get('exploit_plan', {}).get('setup_steps', []))
                exec_steps = len(plan_data.get('exploit_plan', {}).get('execution_steps', []))
                valid_steps = len(plan_data.get('exploit_plan', {}).get('validation_steps', []))

                # Emit status with plan summary
                socketio.emit('agent_status', {
                    'job_id': self.job_id,
                    'agent': 'exploiter',
                    'status': 'Plan created',
                    'detail': f'Exploit plan has {setup_steps} setup, {exec_steps} execution, and {valid_steps} validation steps'
                })

                print(f"Emitting agent_complete event for exploiter for job {self.job_id}")
                socketio.emit('agent_complete', {
                    'job_id': self.job_id,
                    'agent': 'exploiter',
                    'result': f'Created exploit plan for {vuln_type}'
                })

                # Skip PoC generation if configured
                if self.model_config.skip_poc_generation:
                    print(f"Skipping PoC generation for job {self.job_id} as requested")
                    # Store just the exploit plan
                    generated_pocs.append({
                        "vulnerability": vul,
                        "exploit_plan": plan_data.get("exploit_plan"),
                    })
                    continue
                    
                # GENERATOR AGENT
                print(f"Emitting agent_active event for generator for job {self.job_id}")
                socketio.emit('agent_active', {
                    'job_id': self.job_id,
                    'agent': 'generator',
                    'status': 'Generating proof-of-concept code',
                    'detail': f'Creating Foundry test for {vuln_type} vulnerability'
                })

                # Emit status for generating the basetest.sol file
                socketio.emit('agent_status', {
                    'job_id': self.job_id,
                    'agent': 'generator',
                    'status': 'Creating helper files',
                    'detail': 'Ensuring required base test files are available'
                })

                # The basetest.sol file is automatically created by the FrontendGeneratorAgent
                # No need to create directories or check for file existence

                # Emit status for code generation
                socketio.emit('agent_status', {
                    'job_id': self.job_id,
                    'agent': 'generator',
                    'status': 'Writing exploit code',
                    'detail': 'Generating Solidity code to demonstrate the vulnerability'
                })

                # Generate the PoC for this vulnerability
                poc_data = self.generator.generate(plan_data)
                filename = os.path.basename(poc_data.get('exploit_file', 'Unknown'))

                # Emit status with file details
                socketio.emit('agent_status', {
                    'job_id': self.job_id,
                    'agent': 'generator',
                    'status': 'Code generated',
                    'detail': f'Generated PoC file: {filename}'
                })

                print(f"Emitting agent_complete event for generator for job {self.job_id}")
                socketio.emit('agent_complete', {
                    'job_id': self.job_id,
                    'agent': 'generator',
                    'result': f'Created {filename}'
                })

                # Run and fix the exploit if auto-run is enabled
                if auto_run_config.get("auto_run", True):
                    # RUNNER AGENT
                    print(f"Emitting agent_active event for runner for job {self.job_id}")
                    socketio.emit('agent_active', {
                        'job_id': self.job_id,
                        'agent': 'runner',
                        'status': 'Executing proof-of-concept',
                        'detail': f'Running Foundry test for {vuln_type}'
                    })

                    # Emit status for executing test
                    socketio.emit('agent_status', {
                        'job_id': self.job_id,
                        'agent': 'runner',
                        'status': 'Running test',
                        'detail': f'Executing {poc_data.get("execution_command", "forge test")}'
                    })

                    # Run the test
                    run_result = self.runner.run_and_fix_exploit(poc_data)

                    # Get detailed results for feedback
                    success = run_result.get('success', False)
                    retries = run_result.get('retries', 0)

                    # Create appropriate status based on result
                    if success:
                        status_detail = f'Test executed successfully on first attempt' if retries == 0 else f'Test fixed and executed successfully after {retries} retries'
                    else:
                        status_detail = f'Test failed after {retries} fix attempts'

                    # Emit status with execution results
                    socketio.emit('agent_status', {
                        'job_id': self.job_id,
                        'agent': 'runner',
                        'status': 'Execution complete',
                        'detail': status_detail
                    })

                    print(f"Emitting agent_complete event for runner for job {self.job_id}")
                    socketio.emit('agent_complete', {
                        'job_id': self.job_id,
                        'agent': 'runner',
                        'result': 'Success' if success else f'Failed after {retries} attempts'
                    })

                    # Add execution results to the PoC data
                    poc_data["execution_results"] = {
                        "success": run_result.get("success", False),
                        "retries": run_result.get("retries", 0),
                        "error": run_result.get("error", ""),
                        "output": run_result.get("output", "")[:500]  # Truncate long outputs
                    }

                generated_pocs.append({
                    "vulnerability": vul,
                    "exploit_plan": plan_data.get("exploit_plan"),
                    "poc_data": poc_data,
                })

        result = {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
        }
        
        # Export report as markdown if configured
        if self.model_config.export_markdown:
            self.export_results_to_markdown(contract_info["source_code"], result)
            
        return result
        
    def export_results_to_markdown(self, contract_code, results):
        """Export analysis results to a markdown file in the uploads directory"""
        from datetime import datetime
        import os
        
        # Create output filename based on the job id
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"analysis_report_{self.job_id}_{timestamp}.md")
        
        print(f"Exporting analysis report to {output_file}")
        
        rechecked_vulns = results.get("rechecked_vulnerabilities", [])
        pocs = results.get("generated_pocs", [])
        
        with open(output_file, "w") as f:
            # Write header
            f.write(f"# Smart Contract Vulnerability Analysis Report\n\n")
            f.write(f"**Job ID:** {self.job_id}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Add a code preview (first few lines)
            code_preview = "\n".join(contract_code.split("\n")[:20]) + "\n..."
            f.write(f"**Contract Preview:**\n\n```solidity\n{code_preview}\n```\n\n")
            
            # Vulnerability summary
            f.write(f"## Vulnerability Summary\n\n")
            if not rechecked_vulns:
                f.write("No vulnerabilities were detected in this contract.\n\n")
            else:
                f.write(f"Found {len(rechecked_vulns)} potential vulnerabilities:\n\n")
                
                # Create a summary table
                f.write("| # | Vulnerability Type | Confidence | Affected Functions |\n")
                f.write("|---|-------------------|------------|--------------------|\n")
                
                for idx, vuln in enumerate(rechecked_vulns, start=1):
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    confidence = float(vuln.get('skeptic_confidence', 0))
                    affected = ', '.join(vuln.get('affected_functions', ['Unknown']))
                    f.write(f"| {idx} | {vuln_type} | {confidence:.2f} | {affected} |\n")
                
                f.write("\n")
            
            # Detailed vulnerability analysis
            if rechecked_vulns:
                f.write("## Detailed Analysis\n\n")
                
                for idx, vuln in enumerate(rechecked_vulns, start=1):
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    confidence = float(vuln.get('skeptic_confidence', 0))
                    
                    f.write(f"### Vulnerability #{idx}: {vuln_type}\n\n")
                    f.write(f"**Confidence:** {confidence:.2f}\n\n")
                    
                    if vuln.get('reasoning'):
                        f.write(f"**Reasoning:**\n\n{vuln.get('reasoning')}\n\n")
                    
                    if vuln.get('validity_reasoning'):
                        f.write(f"**Validation:**\n\n{vuln.get('validity_reasoning')}\n\n")
                    
                    if vuln.get('code_snippet'):
                        f.write(f"**Code Snippet:**\n\n```solidity\n{vuln.get('code_snippet')}\n```\n\n")
                    
                    if vuln.get('affected_functions'):
                        f.write(f"**Affected Functions:** {', '.join(vuln.get('affected_functions'))}\n\n")
                    
                    # Look for a corresponding PoC
                    matching_poc = next((p for p in pocs if p["vulnerability"].get("vulnerability_type") == vuln_type), None)
                    if matching_poc and matching_poc.get("exploit_plan"):
                        f.write("**Exploit Plan:**\n\n")
                        
                        # Add all steps from the exploit plan
                        plan = matching_poc["exploit_plan"]
                        
                        if plan.get("setup_steps"):
                            f.write("*Setup Steps:*\n\n")
                            for step in plan.get("setup_steps", []):
                                f.write(f"- {step}\n")
                            f.write("\n")
                        
                        if plan.get("execution_steps"):
                            f.write("*Execution Steps:*\n\n")
                            for step in plan.get("execution_steps", []):
                                f.write(f"- {step}\n")
                            f.write("\n")
                        
                        if plan.get("validation_steps"):
                            f.write("*Validation Steps:*\n\n")
                            for step in plan.get("validation_steps", []):
                                f.write(f"- {step}\n")
                            f.write("\n")
                    
                    # Add a separator between vulnerabilities
                    f.write("---\n\n")
            
            # PoC information if any were generated and not skipped
            if pocs and any("poc_data" in poc for poc in pocs):
                f.write("## Proof of Concept Exploits\n\n")
                
                for idx, poc in enumerate(pocs, start=1):
                    if "poc_data" not in poc:
                        continue
                        
                    vuln = poc['vulnerability']
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    
                    f.write(f"### PoC #{idx}: {vuln_type}\n\n")
                    
                    poc_data = poc["poc_data"]
                    f.write(f"**File:** {poc_data.get('exploit_file', 'N/A')}\n\n")
                    
                    # Add execution results if available
                    if "execution_results" in poc_data:
                        results = poc_data["execution_results"]
                        if results.get("success"):
                            f.write("**Execution:** ✅ SUCCESS\n\n")
                        else:
                            f.write(f"**Execution:** ❌ FAILED after {results.get('retries', 0)} fix attempts\n\n")
                            
                            if results.get("error"):
                                f.write(f"**Error:** {results.get('error')}\n\n")
                    
                    # Add PoC code if available
                    if poc_data.get("exploit_code"):
                        f.write("**Exploit Code:**\n\n```solidity\n")
                        f.write(poc_data.get("exploit_code"))
                        f.write("\n```\n\n")
                    
                    # Add a separator between PoCs
                    f.write("---\n\n")
            
            # Footer with recommendations
            f.write("## Recommendations\n\n")
            f.write("For each identified vulnerability, consider implementing the following mitigations:\n\n")
            
            # Add generic recommendations based on found vulnerability types
            vuln_types = [v.get('vulnerability_type', '').lower() for v in rechecked_vulns]
            
            if any('reentrancy' in vt for vt in vuln_types):
                f.write("- **For Reentrancy**: Implement checks-effects-interactions pattern and consider using ReentrancyGuard.\n")
            
            if any('overflow' in vt or 'underflow' in vt or 'arithmetic' in vt for vt in vuln_types):
                f.write("- **For Arithmetic Issues**: Use SafeMath library or Solidity 0.8.x built-in overflow checking.\n")
            
            if any('access' in vt or 'authorization' in vt or 'permission' in vt for vt in vuln_types):
                f.write("- **For Access Control**: Implement proper authorization checks and use the Ownable pattern.\n")
            
            if any('oracle' in vt or 'price' in vt for vt in vuln_types):
                f.write("- **For Oracle Manipulation**: Use time-weighted average prices and multiple independent oracle sources.\n")
            
            # Add a general recommendation
            f.write("- **For All Vulnerabilities**: Consider a professional audit before deploying to production.\n\n")
            
            f.write("*This report was generated automatically by the Smart Contract Vulnerability Analyzer.*\n")
        
        # Also emit an event to notify the frontend
        socketio.emit('report_exported', {
            'job_id': self.job_id,
            'report_path': os.path.basename(output_file),
            'filename': os.path.basename(output_file)
        })

if __name__ == '__main__':
    # Match the port with your socket in the frontend
    socketio.run(app, debug=True, host='0.0.0.0', port=3000)
