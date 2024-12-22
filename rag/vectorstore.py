# rag/vectorstore.py

import os
from typing import List, Dict
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from langchain.docstore.document import Document
from .knowledge_base import VULNERABILITY_DOCS

class VulnerabilityKB:
    def __init__(self):
        # Initialize embeddings with OpenAI API
        self.embeddings = OpenAIEmbeddings(
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

        # Text splitter for chunking docs
        self.text_splitter = CharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )

        # Create vector store
        self.vectorstore = self._initialize_vectorstore()

    def _initialize_vectorstore(self):
        """Initialize FAISS vector store with vulnerability docs"""
        # Convert vulnerability docs to text chunks
        docs = []
        for vuln_doc in VULNERABILITY_DOCS:
            # Create document for each section
            docs.extend([
                Document(
                    page_content=vuln_doc.description,
                    metadata={"type": "description", "name": vuln_doc.name}
                ),
                Document(
                    page_content=vuln_doc.scenario,
                    metadata={"type": "scenario", "name": vuln_doc.name}
                ),
                Document(
                    page_content="\n".join(vuln_doc.code_patterns),
                    metadata={"type": "patterns", "name": vuln_doc.name}
                ),
                Document(
                    page_content="\n".join(vuln_doc.prevention),
                    metadata={"type": "prevention", "name": vuln_doc.name}
                ),
                Document(
                    page_content=str(vuln_doc.exploit_template),
                    metadata={"type": "exploit", "name": vuln_doc.name}
                )
            ])

        # Split into chunks
        chunks = self.text_splitter.split_documents(docs)

        # Create vector store
        return FAISS.from_documents(chunks, self.embeddings)

    def query_knowledge_base(self, query: str, k: int = 10) -> List[Document]:
        """
        Perform a similarity search on the Knowledge Base with an enhanced query.

        Args:
            query (str): The comprehensive query based on the entire contract.
            k (int): Number of top relevant documents to retrieve.

        Returns:
            List[Document]: List of relevant documents from the KB.
        """
        # Add vulnerability pattern context to query
        enhanced_query = f"""
        Vulnerability context: {query}
        Common patterns:
        - State variable modifications
        - External calls
        - Access control mechanisms
        - Control flow patterns
        - Price calculations
        - Token operations
        """

        return self.vectorstore.similarity_search(enhanced_query, k=k)

    def get_exploit_template(self, vuln_name: str) -> Dict[str, str]:
        """
        Retrieve the exploit template for a specific vulnerability.

        Args:
            vuln_name (str): The name of the vulnerability.

        Returns:
            Dict[str, str]: The exploit template containing setup, execution, and validation steps.
        """
        for doc in VULNERABILITY_DOCS:
            if doc.name.lower() == vuln_name.lower():
                return doc.exploit_template
        return None

# Usage example
if __name__ == "__main__":
    kb = VulnerabilityKB()

    # Query for reentrancy patterns
    results = kb.query_knowledge_base(
        "What are code patterns indicating reentrancy?"
    )

    for doc in results:
        print(f"Document type: {doc.metadata['type']}")
        print(f"Content: {doc.page_content}\n")

    # Get exploit template
    template = kb.get_exploit_template("Reentrancy")
    print("Exploit template:", template)
