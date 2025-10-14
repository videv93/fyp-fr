"""
Script to crawl Solodit checklist vulnerabilities using Chrome DevTools MCP
This script extracts all vulnerability categories, subcategories, and questions
from https://solodit.cyfrin.io/checklist
"""

import json
import time
from typing import Dict, List, Any

# This will be populated by extracting data from the browser
CATEGORIES = [
    "Attacker's Mindset",
    "Basics",
    "Centralization Risk",
    "Defi",
    "External Call",
    "Hash / Merkle Tree",
    "Heuristics",
    "Integrations",
    "Low Level",
    "Multi-chain/Cross-chain",
    "Signature",
    "Timelock",
    "Token",
    "Version Issues"
]

def extract_category_data(category_name: str) -> Dict[str, Any]:
    """
    JavaScript code to extract data for a single category
    This should be executed via Chrome DevTools MCP
    """
    js_code = f"""
    async () => {{
      const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
      const categoryName = "{category_name}";

      // Click the category button
      const categoryBtn = Array.from(document.querySelectorAll('button')).find(btn => {{
        return btn.textContent.trim().startsWith(categoryName);
      }});

      if (categoryBtn) {{
        categoryBtn.click();
        await sleep(600);
      }}

      const categoryData = {{
        name: categoryName,
        subcategories: []
      }};

      // Get all buttons with chevron icons (expandable)
      const allButtons = Array.from(document.querySelectorAll('button')).filter(btn => {{
        return btn.querySelector('svg') && btn.textContent.trim().length > 10;
      }});

      // Find subcategory headers (not questions)
      const subcategoryButtons = allButtons.filter(btn => {{
        const text = btn.textContent.trim();
        return !text.startsWith('Is ') && !text.startsWith('Can ') &&
               !text.startsWith('Does ') && !text.startsWith('How ') &&
               !text.startsWith('What ') && !text.startsWith('Are ') &&
               !text.startsWith('Should ') && !text.includes(' 0/') &&
               text !== categoryName;
      }});

      // Process each subcategory
      for (const subBtn of subcategoryButtons) {{
        const subcategoryName = subBtn.textContent.trim();

        // Expand subcategory
        subBtn.click();
        await sleep(400);

        const subcategoryData = {{
          name: subcategoryName,
          questions: []
        }};

        // Get all question buttons now visible
        const questionButtons = Array.from(document.querySelectorAll('button')).filter(btn => {{
          const text = btn.textContent.trim();
          return (text.startsWith('Is ') || text.startsWith('Can ') ||
                 text.startsWith('Does ') || text.startsWith('How ') ||
                 text.startsWith('What ') || text.startsWith('Are ') ||
                 text.startsWith('Should ')) && btn.querySelector('svg');
        }});

        // Process each question
        for (const qBtn of questionButtons) {{
          const questionText = qBtn.textContent.trim();

          // Expand question
          qBtn.click();
          await sleep(250);

          // Get the expanded content
          const mainContent = document.querySelector('main');
          const fullText = mainContent ? mainContent.innerText : '';
          const lines = fullText.split('\\n');

          let description = '';
          let remediation = '';
          let references = [];

          // Find Description section
          const descIndex = lines.findIndex(l => l.trim() === 'Description');
          if (descIndex >= 0 && descIndex < lines.length - 1) {{
            let desc = [];
            for (let i = descIndex + 1; i < lines.length; i++) {{
              if (lines[i].trim() === 'Remediation' || lines[i].trim() === 'References') {{
                break;
              }}
              if (lines[i].trim()) {{
                desc.push(lines[i].trim());
              }}
            }}
            description = desc.join(' ');
          }}

          // Find Remediation section
          const remIndex = lines.findIndex(l => l.trim() === 'Remediation');
          if (remIndex >= 0 && remIndex < lines.length - 1) {{
            let rem = [];
            for (let i = remIndex + 1; i < lines.length; i++) {{
              if (lines[i].trim() === 'References' || lines[i].trim() === 'Description') {{
                break;
              }}
              if (lines[i].trim()) {{
                rem.push(lines[i].trim());
              }}
            }}
            remediation = rem.join(' ');
          }}

          // Get reference links
          const refLinks = mainContent.querySelectorAll('a[href*="solodit.cyfrin.io/issues"]');
          references = Array.from(refLinks).map(a => a.href);

          subcategoryData.questions.push({{
            question: questionText,
            description: description,
            remediation: remediation,
            references: references
          }});

          // Collapse question
          qBtn.click();
          await sleep(150);
        }}

        categoryData.subcategories.push(subcategoryData);

        // Collapse subcategory
        subBtn.click();
        await sleep(300);
      }}

      return categoryData;
    }}
    """
    return js_code

def main():
    """
    Main function to orchestrate the crawling
    """
    all_vulnerabilities = {}

    print("=" * 80)
    print("Solodit Checklist Vulnerability Crawler")
    print("=" * 80)
    print(f"\\nTotal categories to process: {len(CATEGORIES)}")
    print("\\nThis script generates JavaScript code for each category.")
    print("Execute each script via Chrome DevTools MCP to extract data.\\n")

    # Generate extraction scripts for each category
    for i, category in enumerate(CATEGORIES, 1):
        print(f"\\n[{i}/{len(CATEGORIES)}] Category: {category}")
        print("-" * 80)
        js_code = extract_category_data(category)
        print(f"Execute this JavaScript code via Chrome DevTools MCP:")
        print(f"\\n{js_code}\\n")
        print("-" * 80)

    print("\\n" + "=" * 80)
    print("After executing all scripts, combine results into a single JSON file.")
    print("=" * 80)

if __name__ == "__main__":
    main()
