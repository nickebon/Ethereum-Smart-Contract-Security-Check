"""
LLM Deduplication Module
Takes combined findings JSON, uses GPT-4 to group duplicates
"""

import os
import json
from typing import List, Dict
from openai import AzureOpenAI
from dotenv import load_dotenv

load_dotenv()

class LLMDeduplicator:
    """Deduplicate findings using LLM semantic understanding"""
    
    def __init__(self):
        # Load Azure OpenAI configuration
        self.endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
        self.api_key = os.getenv("AZURE_OPENAI_KEY")
        self.api_version = os.getenv("AZURE_OPENAI_API_VERSION")
        
        # Debug output
        print("🔧 Initializing LLM Deduplicator...")
        print(f"   Endpoint: {self.endpoint}")
        print(f"   Deployment: {self.deployment}")
        print(f"   API Version: {self.api_version}")
        print(f"   Key loaded: {self.api_key is not None}")
        
        # Initialize Azure OpenAI client
        self.client = AzureOpenAI(
            api_version=self.api_version,
            azure_endpoint=self.endpoint,
            api_key=self.api_key,
        )
        
        print("✓ Client initialized successfully\n")
    
    def deduplicate(self, findings: List[Dict]) -> Dict:
        """
        Group related findings that describe same vulnerability
        
        Args:
            findings: List of parsed Finding dicts
        
        Returns:
            {
                'unique_vulnerabilities': [...],
                'summary': {...}
            }
        """
        
        prompt = self._build_prompt(findings)
        
        print(f"📤 Sending {len(findings)} findings to LLM...")
        
        try:
            response = self.client.chat.completions.create(
                model=self.deployment,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a smart contract security expert. You analyze vulnerability findings and identify duplicates."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0,  # Deterministic
                max_completion_tokens=4096  # Match your working config
            )
            
            print("✓ LLM response received\n")

            # Parse JSON response (strip markdown fences if present)
            raw_content = response.choices[0].message.content

            # Remove markdown code fences if LLM wrapped the response
            if raw_content.strip().startswith("```"):
                # Extract content between ```json and ```
                lines = raw_content.strip().split('\n')
                # Remove first line (```json) and last line (```)
                json_content = '\n'.join(lines[1:-1])
            else:
                json_content = raw_content

            result = json.loads(json_content)
            
            # Add metadata
            result['llm_model'] = self.deployment
            result['input_count'] = len(findings)
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing error: {e}")
            print(f"Raw response: {response.choices[0].message.content}")
            return {
                'unique_vulnerabilities': [],
                'error': f'JSON parse error: {str(e)}'
            }
        except Exception as e:
            print(f"❌ LLM error: {e}")
            return {
                'unique_vulnerabilities': [],
                'error': str(e)
            }
    
    def _build_prompt(self, findings: List[Dict]) -> str:
        """Build deduplication prompt"""
        
        # Simplify findings for LLM (remove noise)
        simplified = []
        for i, f in enumerate(findings):
            simplified.append({
                'id': i,
                'tool': f.get('tool'),
                'check': f.get('check'),
                'severity': f.get('severity'),
                'function': f.get('function'),
                'lines': f.get('lines'),
                'description': f.get('description', '')[:200]  # truncate
            })
        
        findings_json = json.dumps(simplified, indent=2)
        
        return f"""You are analyzing smart contract security findings from Slither and Mythril.

PROBLEM: Multiple alerts often describe the SAME underlying vulnerability.

Example:
- Alert 0: Mythril "External Call" on line 19
- Alert 1: Mythril "State access after external call" on line 20
- Alert 2: Slither "reentrancy-eth" in withdraw()

These 3 alerts likely describe ONE reentrancy bug.

FINDINGS TO ANALYZE:
{findings_json}

TASK:
1. Identify which findings refer to the same underlying vulnerability
2. Group related findings based on:
   - Spatial proximity (same function, nearby lines)
   - Logical relationships (external call → state change pattern)
   - Tool agreement on vulnerability type

3. For each unique vulnerability, provide:
   - Primary name (e.g., "Reentrancy in withdraw()")
   - SWC ID if applicable
   - Unified severity (use highest from group)
   - Which finding IDs belong to this group
   - Brief reasoning

OUTPUT (JSON only, no explanation):
{{
  "unique_vulnerabilities": [
    {{
      "vuln_id": 1,
      "name": "Reentrancy in withdraw()",
      "swc_id": "SWC-107",
      "severity": "high",
      "location": "withdraw() function, lines 16-22",
      "finding_ids": [0, 1, 4],
      "reasoning": "All three alerts reference the external call on line 19 followed by state change on line 20"
    }}
  ],
  "summary": {{
    "total_input": {len(findings)},
    "unique_count": 3,
    "duplicates_removed": 6
  }}
}}

RULES:
- Only group findings that clearly describe the same issue
- If unsure, keep separate (precision > recall)
- Use SWC-107 for reentrancy, SWC-104 for unchecked returns, etc.
- Output MUST be valid JSON with no additional text
"""


def main():
    """Test on SimpleDAO combined findings"""
    
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python llm_deduplicator.py <combined.json>")
        sys.exit(1)
    
    # Load combined findings
    with open(sys.argv[1]) as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    
    print(f"\n📊 Input: {len(findings)} findings")
    print("=" * 60)
    print("Running LLM deduplication...\n")
    
    # Deduplicate
    deduplicator = LLMDeduplicator()
    result = deduplicator.deduplicate(findings)
    
    # Display results
    print("=" * 60)
    print("DEDUPLICATION RESULTS")
    print("=" * 60)
    
    if 'error' in result:
        print(f"❌ Error: {result['error']}")
        return
    
    summary = result.get('summary', {})
    print(f"\nInput:  {summary.get('total_input', 0)} findings")
    print(f"Output: {summary.get('unique_count', 0)} unique vulnerabilities")
    print(f"Removed: {summary.get('duplicates_removed', 0)} duplicates")
    
    print("\n" + "=" * 60)
    print("UNIQUE VULNERABILITIES")
    print("=" * 60)
    
    for vuln in result.get('unique_vulnerabilities', []):
        print(f"\n[{vuln.get('vuln_id')}] {vuln.get('name')}")
        print(f"    SWC: {vuln.get('swc_id', 'N/A')}")
        print(f"    Severity: {vuln.get('severity', 'unknown').upper()}")
        print(f"    Location: {vuln.get('location')}")
        print(f"    Groups findings: {vuln.get('finding_ids')}")
        print(f"    Reasoning: {vuln.get('reasoning')}")
    
    # Save output
    output_path = sys.argv[1].replace('_combined.json', '_deduplicated.json')
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n✓ Saved to: {output_path}")
    print("=" * 60)


if __name__ == '__main__':
    main()