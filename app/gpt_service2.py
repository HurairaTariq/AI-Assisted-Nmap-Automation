import json
import httpx
from app.config import settings
from app.mcp_tools import MCP_TOOLS, SYSTEM_PROMPT

# Ollama config
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3"  # you can change to mistral, llama3:8b, etc.


# -----------------------------
# Core Ollama call function
# -----------------------------
async def call_ollama(messages, temperature=0):
    print("\n=== OLLAMA CALL START ===")
    print("URL:", OLLAMA_URL)
    print("MODEL:", MODEL)
    print("TEMPERATURE:", temperature)
    print("MESSAGES:", messages)

    async with httpx.AsyncClient(timeout=360) as client:
        response = await client.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": messages,
                "options": {
                    "temperature": temperature
                },
                "stream": False
            }
        )

        print("STATUS CODE:", response.status_code)
        print("RAW RESPONSE TEXT:", response.text[:1000])
        print("=== OLLAMA CALL END ===\n")

        response.raise_for_status()
        return response.json()["message"]["content"]


# -----------------------------
# Tool Proposal (GPT replacement)
# -----------------------------
async def get_tool_proposal(nl_query: str) -> dict:
    """
    Simulate function-calling using structured JSON output from Ollama.
    Returns:
    - { tool_name, params }
    - OR { error, reason }
    """

    tool_desc = json.dumps(MCP_TOOLS, indent=2)

    prompt = f"""
You are an AI that selects exactly one tool and its parameters.

Available tools:
{tool_desc}

STRICT RULES:
- Return ONLY valid JSON
- No markdown
- No explanations
- No extra text
- The first key MUST be "tool_name"
- "tool_name" must be a string
- The second key MUST be "params"
- "params" must be an object
- Never output this invalid form:
  {{
    "port_scan",
    "params": {{ ... }}
  }}

VALID OUTPUT EXAMPLES:
{{
  "tool_name": "port_scan",
  "params": {{
    "target": "192.168.1.10",
    "ports": "80,443",
    "scan_type": "syn"
  }}
}}

{{
  "tool_name": "host_discovery",
  "params": {{
    "target": "192.168.1.0/24"
  }}
}}

If the request is out of scope, return exactly:
{{
  "error": "out_of_scope",
  "reason": "Request is not a valid safe network scan"
}}

User request:
{nl_query}
"""

    content = await call_ollama([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ])

    # Try parsing JSON safely
    try:
        parsed = json.loads(content)

        # Validate basic structure
        if "tool_name" in parsed and "params" in parsed:
            return parsed

        if "error" in parsed:
            return parsed

        return {
            "error": "invalid_structure",
            "raw_output": content
        }
    except json.JSONDecodeError:
        return {
            "error": "invalid_json",
            "raw_output": content
        }


# -----------------------------
# Result Summarisation
# -----------------------------
async def summarise_results(nmap_findings: dict) -> str:
    """
    Deterministic summary from parsed findings.
    No LLM call.
    """
    hosts = nmap_findings.get("hosts", [])
    if not hosts:
        return "Scan completed. No hosts were found in the parsed results."

    host = hosts[0]
    address = host.get("address", "unknown target")
    status = host.get("status", "unknown")
    ports = host.get("ports", [])

    if not ports:
        return f"Scan completed. Host {address} is {status}. No port results were returned."

    open_ports = [str(p["port"]) for p in ports if p.get("state") == "open"]
    closed_ports = [str(p["port"]) for p in ports if p.get("state") == "closed"]

    if open_ports:
        return (
            f"Scan completed. Host {address} is {status}. "
            f"Open ports found: {', '.join(open_ports)}."
        )

    if closed_ports:
        return (
            f"Scan completed. Host {address} is {status}. "
            f"Ports {', '.join(closed_ports)} were scanned and all were closed."
        )

    return f"Scan completed. Host {address} is {status}. Port results were returned."