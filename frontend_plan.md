# Smart Contract Vulnerability Analyzer Frontend

## Overview
This document outlines the implementation plan for a frontend interface for the Smart Contract Vulnerability Analyzer system. The frontend will provide a user-friendly way to interact with the multi-agent system, submit contracts for analysis, and visualize the results.

## Architecture

### Frontend Stack
- **React**: For building the user interface
- **Tailwind CSS**: For styling
- **Axios**: For making API requests to the backend
- **Socket.io-client**: For real-time updates during analysis
- **React Flow**: For visualizing the multi-agent workflow
- **CodeMirror**: For displaying and highlighting Solidity code

### Backend Integration
- Create a Flask or FastAPI wrapper around the existing Python codebase
- Implement WebSocket support for real-time updates
- Expose API endpoints for contract upload, address fetching, and analysis

## Features

### 1. Contract Input
- **File Upload Zone**
  - Drag-and-drop area for uploading .sol files
  - Multi-file support for projects with dependencies
  - File validation to ensure Solidity files
  
- **Blockchain Explorer Integration**
  - Input field for contract addresses
  - Network selector (Ethereum, BSC, Polygon, etc.)
  - Fetch button to retrieve contract source code using `source_code_fetcher.py`

### 2. Analysis Controls
- Start Analysis button
- Model selection dropdowns (for each agent)
- Analysis options panel (auto-run, max retries, etc.)

### 3. Multi-Agent Visualization
- Interactive flow diagram showing the agents and their relationships:
  - **Analyzer Agent**: Initial vulnerability detection
  - **Skeptic Agent**: Validation of potential vulnerabilities
  - **Exploiter Agent**: Generating exploit plans
  - **Generator Agent**: Creating PoC contracts
  - **Runner Agent**: Testing and fixing exploits
- Real-time status indicators showing active agent
- Progress indicators for each agent

### 4. Results Display
- **Vulnerabilities Panel**
  - List of detected vulnerabilities sorted by confidence
  - Details view showing:
    - Vulnerability type
    - Confidence score
    - Affected functions
    - Code snippets with highlighting
    - Reasoning and validity assessment
  
- **Exploit Plans Panel**
  - Setup steps
  - Execution steps
  - Validation steps
  
- **PoC Code Display**
  - Syntax-highlighted code viewer
  - Copy button
  - Download button
  - Open in Remix button (if possible)
  
- **Execution Results**
  - Test success/failure status
  - Error messages if applicable
  - Fix attempts if any

## Implementation Plan

### Phase 1: Backend API
1. Create a new Flask/FastAPI application
2. Implement file upload and contract address endpoints
3. Wrap existing agent coordinator in an async job system
4. Add WebSocket support for real-time updates

### Phase 2: Frontend Core
1. Set up React application with Tailwind CSS
2. Implement file upload and address input components
3. Create basic results display components
4. Implement API service for interacting with backend

### Phase 3: Visualization and Real-Time Updates
1. Implement agent workflow visualization with React Flow
2. Add WebSocket client for real-time updates
3. Create animations and transitions for agent states
4. Implement code highlighting and vulnerability marking

### Phase 4: Advanced Features
1. Add syntax highlighting for Solidity code
2. Implement PoC execution in-browser (if possible)
3. Add export functionality for reports
4. Implement user authentication (optional)

## API Endpoints

### Contract Input
- `POST /api/upload-contract`: Upload Solidity file(s)
- `POST /api/fetch-contract`: Fetch contract from blockchain by address

### Analysis
- `POST /api/analyze`: Start analysis with options
- `GET /api/status/:jobId`: Get analysis status
- `GET /api/results/:jobId`: Get analysis results

### WebSocket Events
- `analysis_started`: Analysis job has started
- `agent_active`: An agent has started processing (with agent name)
- `agent_complete`: An agent has completed processing (with result summary)
- `vulnerability_found`: New vulnerability detected
- `poc_generated`: PoC contract has been generated
- `test_result`: Result of test execution
- `analysis_complete`: Full analysis completed with results

## UI Mockups
[Include mockups or wireframes here]

## Next Steps
1. Finalize technology stack
2. Create detailed wireframes
3. Set up development environment
4. Implement backend API wrapper
5. Start frontend development