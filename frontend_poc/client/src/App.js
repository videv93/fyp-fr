import React, { useState, useEffect, useRef } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Header from "./components/Header";
import ContractInput from "./components/ContractInput";
import AnalysisOptions from "./components/AnalysisOptions";
import AgentVisualizer from "./components/AgentVisualizer";
import VulnerabilitiesPanel from "./components/VulnerabilitiesPanel";
import ExploitsPanel from "./components/ExploitsPanel";
import { io } from "socket.io-client";
import {
  fetchContractStatus,
  fetchContractResults,
  startAnalysis,
} from "./services/api";
import "./App.css";

// Initialize socket.io client - make sure port matches your backend
const socket = io("http://localhost:3000");

function App() {
  const [currentJob, setCurrentJob] = useState(null);
  const [jobStatus, setJobStatus] = useState("idle");
  const [analysisResults, setAnalysisResults] = useState(null);
  const [activeAgent, setActiveAgent] = useState(null);
  const [completedAgents, setCompletedAgents] = useState([]);
  const [analysisOptions, setAnalysisOptions] = useState({
    analyzer_model: "o3-mini",
    skeptic_model: "o3-mini",
    exploiter_model: "o3-mini",
    generator_model: "o3-mini",
    auto_run: true,
    max_retries: 3,
    use_rag: true,
  });

  // Keep a reference to currentJob that won't cause effect hook to re-run
  const currentJobRef = useRef(null);

  useEffect(() => {
    currentJobRef.current = currentJob;
  }, [currentJob]);

  // Connect to Socket.io for real-time updates
  useEffect(() => {
    console.log("Setting up socket listeners");

    // Set up socket event listeners
    const onConnect = () => {
      console.log("Connected to server");
    };

    const onAnalysisStarted = (data) => {
      console.log("Analysis started event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("analyzing");
      }
    };

    const onAgentActive = (data) => {
      console.log("Agent active event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setActiveAgent(data.agent);
      }
    };

    const onAgentComplete = (data) => {
      console.log("Agent complete event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        const agent = data.agent;

        // Add to completed agents list
        setCompletedAgents((prev) => {
          if (!prev.includes(agent)) {
            return [...prev, agent];
          }
          return prev;
        });

        // If this agent was active, clear it
        setActiveAgent((prev) => (prev === agent ? null : prev));
      }
    };

    const onAnalysisComplete = async (data) => {
      console.log("Analysis complete event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("completed");
        setActiveAgent(null);

        // Fetch full results
        try {
          const results = await fetchContractResults(data.job_id);
          setAnalysisResults(results.data.results);
        } catch (error) {
          console.error("Error fetching results:", error);
        }
      }
    };

    const onAnalysisError = (data) => {
      console.log("Analysis error event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("error");
        setActiveAgent(null);
      }
    };

    const onContractFetched = (data) => {
      console.log("Contract fetched event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("fetched");
      }
    };

    const onContractFetchError = (data) => {
      console.log("Contract fetch error event:", data);
      if (currentJobRef.current?.id === data.job_id) {
        setJobStatus("error");
      }
    };

    socket.on("connect", onConnect);
    socket.on("analysis_started", onAnalysisStarted);
    socket.on("agent_active", onAgentActive);
    socket.on("agent_complete", onAgentComplete);
    socket.on("analysis_complete", onAnalysisComplete);
    socket.on("analysis_error", onAnalysisError);
    socket.on("contract_fetched", onContractFetched);
    socket.on("contract_fetch_error", onContractFetchError);

    // Clean up on unmount
    return () => {
      console.log("Cleaning up socket listeners");
      socket.off("connect", onConnect);
      socket.off("analysis_started", onAnalysisStarted);
      socket.off("agent_active", onAgentActive);
      socket.off("agent_complete", onAgentComplete);
      socket.off("analysis_complete", onAnalysisComplete);
      socket.off("analysis_error", onAnalysisError);
      socket.off("contract_fetched", onContractFetched);
      socket.off("contract_fetch_error", onContractFetchError);
    };
  }, []); // Empty dependency array to set up only once

  // Poll job status if not completed or error
  useEffect(() => {
    let interval;
    if (
      currentJob &&
      ["uploaded", "fetched", "analyzing"].includes(jobStatus)
    ) {
      interval = setInterval(async () => {
        try {
          const response = await fetchContractStatus(currentJob.id);
          setJobStatus(response.data.status);

          if (response.data.status === "completed") {
            const results = await fetchContractResults(currentJob.id);
            setAnalysisResults(results.data.results);
            clearInterval(interval);
          } else if (response.data.status === "error") {
            clearInterval(interval);
          }
        } catch (error) {
          console.error("Error polling job status:", error);
        }
      }, 5000);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [currentJob, jobStatus]);

  const handleContractSubmit = (jobData) => {
    setCurrentJob(jobData);
    setJobStatus(jobData.status);
    setAnalysisResults(null);
    setActiveAgent(null);
    setCompletedAgents([]); // Reset completed agents
  };

  const handleStartAnalysis = async () => {
    if (!currentJob) return;

    try {
      await startAnalysis({
        job_id: currentJob.id,
        ...analysisOptions,
      });
      setJobStatus("analyzing");
    } catch (error) {
      console.error("Error starting analysis:", error);
    }
  };

  const handleOptionsChange = (options) => {
    setAnalysisOptions({
      ...analysisOptions,
      ...options,
    });
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <Header />

        <main className="container mx-auto p-4 md:p-6 max-w-7xl">
          <Routes>
            <Route
              path="/"
              element={
                <>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                    <ContractInput onContractSubmit={handleContractSubmit} />
                    <AnalysisOptions
                      options={analysisOptions}
                      onChange={handleOptionsChange}
                      onStartAnalysis={handleStartAnalysis}
                      isReady={
                        currentJob &&
                        ["uploaded", "fetched"].includes(jobStatus)
                      }
                      isAnalyzing={jobStatus === "analyzing"}
                    />
                  </div>

                  {currentJob && (
                    <div className="mb-8">
                      <AgentVisualizer
                        activeAgent={activeAgent}
                        status={jobStatus}
                        completedAgents={completedAgents}
                      />
                    </div>
                  )}

                  {analysisResults && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <VulnerabilitiesPanel
                        vulnerabilities={
                          analysisResults.rechecked_vulnerabilities || []
                        }
                      />
                      <ExploitsPanel
                        exploits={analysisResults.generated_pocs || []}
                      />
                    </div>
                  )}
                </>
              }
            />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
