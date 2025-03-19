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
            args=(job_id, data['network'], data['address'], output_file)
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
        print(f"Fetching contract for {address} on {network}...")
        fetch_and_flatten_contract(network, address, output_file)

        print(f"Contract fetched successfully, updating job {job_id} status to 'fetched'")
        jobs[job_id].update({
            'status': 'fetched',
            'contract_path': output_file,
            'filename': f"{address}.sol"
        })

        print(f"Emitting contract_fetched event for job {job_id}")
        socketio.emit('contract_fetched', {'job_id': job_id, 'status': 'fetched'})
    except Exception as e:
        print(f"Error fetching contract: {str(e)}")
        jobs[job_id].update({
            'status': 'error',
            'error': str(e)
        })
        print(f"Emitting contract_fetch_error event for job {job_id}")
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
        socketio.emit('agent_active', {'job_id': job_id, 'agent': 'static_analyzer'})

        function_details, call_graph, detector_results = analyze_contract(contract_path)

        print(f"Emitting agent_complete event for static_analyzer for job {job_id}")
        socketio.emit('agent_complete', {
            'job_id': job_id,
            'agent': 'static_analyzer'
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

        # Save the contract to a file using our custom method
        filename = self.save_poc_locally(contract_code, vuln_type)

        # For the forge test command, we need to use just the relative path from within the exploit dir
        rel_path = os.path.basename(filename)
        if "src/test" in filename:
            rel_path = filename.split("exploit/")[-1] if "exploit/" in filename else filename

        return {
            "exploit_code": contract_code,
            "exploit_file": filename,
            "execution_command": f"forge test -vv --match-path {rel_path}"
        }

    def save_poc_locally(self, poc_code: str, vuln_type: str) -> str:
        """
        Save the generated PoC contract to a file in the frontend_poc/exploit directory

        Args:
            poc_code: The Solidity code
            vuln_type: Type of vulnerability

        Returns:
            The filename where the code was saved
        """
        # Create exploit directory if it doesn't exist
        frontend_exploit_dir = os.path.join(os.getcwd(), "frontend_poc", "exploit")
        os.makedirs(os.path.join(frontend_exploit_dir, "src", "test"), exist_ok=True)

        ts = int(time.time())
        rel_filename = f"src/test/PoC_{vuln_type}_{ts}.sol"
        abs_filename = os.path.join(frontend_exploit_dir, rel_filename)

        with open(abs_filename, "w", encoding="utf-8") as f:
            f.write(poc_code)

        print(f"PoC saved to {abs_filename}")
        return abs_filename

    def generate_basetest_file(self) -> str:
        """Generate basetest.sol and save it to frontend_poc/exploit/src/test/basetest.sol"""
        # Create the file path
        frontend_exploit_dir = os.path.join(os.getcwd(), "frontend_poc", "exploit")
        abs_filename = os.path.join(frontend_exploit_dir, "src", "test", "basetest.sol")

        # Generate the basetest file content
        basetest_content = self._generate_basetest_content()

        # Save the file
        with open(abs_filename, "w", encoding="utf-8") as f:
            f.write(basetest_content)

        return abs_filename

# Modified version of ExploitRunner for the frontend
class FrontendExploitRunner(ExploitRunner):
    def _execute_test(self, command: str) -> Tuple[bool, str, str]:
        """
        Execute a Foundry test command and capture the output.
        Uses frontend_poc/exploit directory.

        Args:
            command: Forge test command to execute

        Returns:
            Tuple of (success, output, error_message)
        """
        try:
            # Use frontend_poc/exploit as the working directory
            frontend_cwd = os.path.join(os.getcwd(), "frontend_poc", "exploit")
            print(f"Executing test in directory: {frontend_cwd}")

            # Execute the command
            result = subprocess.run(
                command,
                shell=True,
                cwd=frontend_cwd,
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
        socketio.emit('agent_active', {'job_id': self.job_id, 'agent': 'analyzer'})
        vuln_results = self.analyzer.analyze(contract_info)
        vulnerabilities = vuln_results.get("vulnerabilities", [])

        print(f"Emitting agent_complete event for analyzer for job {self.job_id}")
        socketio.emit('agent_complete', {
            'job_id': self.job_id,
            'agent': 'analyzer'
        })

        if not vulnerabilities:
            return {"status": "no_vulnerability_found"}

        # 2. Skeptic => re-check validity
        print(f"Emitting agent_active event for skeptic for job {self.job_id}")
        socketio.emit('agent_active', {'job_id': self.job_id, 'agent': 'skeptic'})
        rechecked_vulns = self.skeptic.audit_vulnerabilities(
            contract_info["source_code"], vulnerabilities
        )

        print(f"Emitting agent_complete event for skeptic for job {self.job_id}")
        socketio.emit('agent_complete', {
            'job_id': self.job_id,
            'agent': 'skeptic'
        })

        # 3. Generate PoCs for high-confidence vulnerabilities
        generated_pocs = []
        high_conf_vulns = [v for v in rechecked_vulns if v.get("skeptic_confidence", 0) > 0.5]

        # Generate for only one for now
        if high_conf_vulns:
            for i, vul in enumerate(high_conf_vulns):
                print(f"Emitting agent_active event for exploiter for job {self.job_id}")
                socketio.emit('agent_active', {'job_id': self.job_id, 'agent': 'exploiter'})
                plan_data = self.exploiter.generate_exploit_plan(vul)

                print(f"Emitting agent_complete event for exploiter for job {self.job_id}")
                socketio.emit('agent_complete', {'job_id': self.job_id, 'agent': 'exploiter'})

                print(f"Emitting agent_active event for generator for job {self.job_id}")
                socketio.emit('agent_active', {'job_id': self.job_id, 'agent': 'generator'})

                # The basetest.sol file is automatically created by the FrontendGeneratorAgent
                # No need to create directories or check for file existence

                # Generate the PoC for this vulnerability
                poc_data = self.generator.generate(plan_data)

                print(f"Emitting agent_complete event for generator for job {self.job_id}")
                socketio.emit('agent_complete', {'job_id': self.job_id, 'agent': 'generator'})

                # Run and fix the exploit if auto-run is enabled
                if auto_run_config.get("auto_run", True):
                    print(f"Emitting agent_active event for runner for job {self.job_id}")
                    socketio.emit('agent_active', {'job_id': self.job_id, 'agent': 'runner'})
                    run_result = self.runner.run_and_fix_exploit(poc_data)

                    print(f"Emitting agent_complete event for runner for job {self.job_id}")
                    socketio.emit('agent_complete', {'job_id': self.job_id, 'agent': 'runner'})

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

        return {
            "rechecked_vulnerabilities": rechecked_vulns,
            "generated_pocs": generated_pocs,
        }

if __name__ == '__main__':
    # Match the port with your socket in the frontend
    socketio.run(app, debug=True, host='0.0.0.0', port=3000)
