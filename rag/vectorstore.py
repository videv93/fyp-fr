import os
from typing import List, Dict, Optional
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from langchain.docstore.document import Document
from .knowledge_base import VULNERABILITY_DOCS
import json

class VulnerabilityKB:
    def __init__(self):
        self.embeddings = OpenAIEmbeddings(
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

        # Use a smaller chunk size to maintain coherence
        self.text_splitter = CharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=100,
            separator="\n"
        )

        # Create vector store
        self.vectorstore = self._initialize_vectorstore()

    def _create_structured_document(self, vuln_doc) -> str:
        """Create a structured representation of the vulnerability document"""
        return f"""
VULNERABILITY: {vuln_doc.name}
-------------------
DESCRIPTION:
{vuln_doc.description}

SCENARIO:
{vuln_doc.scenario}

PROPERTY:
{vuln_doc.property}

IMPACT:
{vuln_doc.impact}

CODE PATTERNS:
{chr(10).join(vuln_doc.code_patterns)}

PREVENTION:
{chr(10).join(vuln_doc.prevention)}

EXPLOIT:
{json.dumps(vuln_doc.exploit_template, indent=2)}
"""

    def _initialize_vectorstore(self):
        """Initialize FAISS vector store with vulnerability docs"""
        docs = []

        for vuln_doc in VULNERABILITY_DOCS:
            # Create a complete structured document
            full_doc = self._create_structured_document(vuln_doc)

            # Split the full document into chunks while preserving context
            chunks = self.text_splitter.create_documents(
                texts=[full_doc],
                metadatas=[{
                    "name": vuln_doc.name,
                    "full_doc": full_doc,  # Store full document for context
                    "description": vuln_doc.description,
                    "impact": vuln_doc.impact,
                    "exploit_template": json.dumps(vuln_doc.exploit_template)
                }]
            )

            docs.extend(chunks)

        return FAISS.from_documents(docs, self.embeddings)

    def query_knowledge_base(
        self,
        query: str,
        k: int = 3,
        filter_type: Optional[str] = None
    ) -> List[Dict]:
        """
        Perform an enhanced similarity search on the Knowledge Base.

        Args:
            query (str): The search query
            k (int): Number of results to return
            filter_type (str): Optional filter for vulnerability type

        Returns:
            List[Dict]: List of relevant vulnerability information
        """
        # Enhance query with context
        enhanced_query = f"""
        Context: Looking for vulnerability information related to:
        {query}

        Consider:
        - Vulnerability patterns and characteristics
        - Potential impact and exploitation scenarios
        - Prevention measures and best practices
        - Related code patterns and implementations
        """

        # Perform similarity search
        results = self.vectorstore.similarity_search_with_score(
            enhanced_query,
            k=k
        )

        # Process and deduplicate results
        processed_results = []
        seen_vulns = set()

        for doc, score in results:
            vuln_name = doc.metadata["name"]

            # Skip if we've already seen this vulnerability
            if vuln_name in seen_vulns:
                continue

            seen_vulns.add(vuln_name)

            # Return full context along with the matching chunk
            processed_results.append({
                "name": vuln_name,
                "relevance_score": score,
                "matching_chunk": doc.page_content,
                "full_context": doc.metadata["full_doc"],
                "description": doc.metadata["description"],
                "impact": doc.metadata["impact"],
                "exploit_template": json.loads(doc.metadata["exploit_template"])
            })

        return processed_results

    def get_vulnerability_details(self, vuln_name: str) -> Optional[Dict]:
        """
        Get complete details for a specific vulnerability.

        Args:
            vuln_name (str): Name of the vulnerability

        Returns:
            Optional[Dict]: Complete vulnerability information
        """
        for vuln_doc in VULNERABILITY_DOCS:
            if vuln_doc.name.lower() == vuln_name.lower():
                return {
                    "name": vuln_doc.name,
                    "description": vuln_doc.description,
                    "scenario": vuln_doc.scenario,
                    "property": vuln_doc.property,
                    "impact": vuln_doc.impact,
                    "code_patterns": vuln_doc.code_patterns,
                    "prevention": vuln_doc.prevention,
                    "exploit_template": vuln_doc.exploit_template
                }
        return None

# Usage example
if __name__ == "__main__":
    kb = VulnerabilityKB()

    # Search for reentrancy vulnerabilities
    results = kb.query_knowledge_base(
        "Show me patterns related to reentrancy attacks in smart contracts"
    )

    for result in results:
        print(f"\nVulnerability: {result['name']}")
        print(f"Relevance Score: {result['relevance_score']}")
        print(f"Matching Content: {result['matching_chunk']}")
        print("\nFull Context Available in result['full_context']")
