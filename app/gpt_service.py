import json
import re
from openai import AsyncOpenAI
from app.config import settings
from app.mcp_tools import MCP_TOOLS, SYSTEM_PROMPT

client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

BLOCKED_WORDS = [
    "fragmentation",
    "fragment",
    "spoof",
    "spoofing",
    "decoy",
    "proxy",
    "exploit",
    "evasion",
    "firewall bypass",
    "ids bypass",
    "stealth",
]


def normalize_ports_expression(text: str) -> str:
    """
    Normalize natural-language port expressions into comma-separated format.
    Examples:
    - 'port 80 and 443' -> 'ports 80,443'
    - 'ports 22, 80 and 443' -> 'ports 22,80,443'
    """
    text = re.sub(
        r"\bport\s+(\d+)\s+and\s+(\d+)\b",
        r"ports \1,\2",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"\bports?\s+([\d,\s]+)\s+and\s+(\d+)\b",
        lambda m: "ports " + m.group(1).replace(" ", "").rstrip(",") + "," + m.group(2),
        text,
        flags=re.IGNORECASE,
    )

    return text


def normalize_scan_words(text: str) -> str:
    """
    Normalize common natural-language scan phrases.
    """
    replacements = {
        r"\bservice detection\b": "service detect",
        r"\bversion detection\b": "service detect",
        r"\bservice scan\b": "service detect",
        r"\bos detection\b": "os detect",
        r"\bdetect os\b": "os detect",
        r"\bhost discovery\b": "host discovery",
        r"\bping scan\b": "host discovery",
        r"\bsyn scan\b": "syn scan",
        r"\bconnect scan\b": "connect scan",
        r"\bcheck open ports\b": "scan ports",
    }

    for pattern, repl in replacements.items():
        text = re.sub(pattern, repl, text, flags=re.IGNORECASE)

    return text


def normalize_query(nl_query: str) -> str:
    """
    General normalization before sending to GPT.
    """
    q = nl_query.strip()
    q = normalize_ports_expression(q)
    q = normalize_scan_words(q)

    # collapse repeated spaces
    q = re.sub(r"\s+", " ", q).strip()
    return q


async def get_tool_proposal(nl_query: str) -> dict:
    """
    Sends the user's normalized natural language query to the OpenAI model
    in tool-calling mode and returns either:

    - {"tool_name": ..., "params": {...}}
    - {"error": ..., "reason": ...}
    """
    q = nl_query.lower()

    # Fast safety gate before model call
    if any(word in q for word in BLOCKED_WORDS):
        return {
            "error": "out_of_scope",
            "reason": "Unsafe scan request",
        }

    normalized_query = normalize_query(nl_query)

    print("\n=== QUERY NORMALIZATION ===")
    print("RAW QUERY:", nl_query)
    print("NORMALIZED QUERY:", normalized_query)
    print("=== END QUERY NORMALIZATION ===\n")

    try:
        response = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            tools=MCP_TOOLS,
            tool_choice="auto",
            temperature=0,
            max_tokens=300,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": normalized_query},
            ],
        )

        msg = response.choices[0].message

        print("\n=== OPENAI TOOL PROPOSAL RESPONSE ===")
        print("MESSAGE CONTENT:", msg.content)
        print("TOOL CALLS:", msg.tool_calls)
        print("=== END OPENAI RESPONSE ===\n")

        # Model selected a tool
        if msg.tool_calls:
            tc = msg.tool_calls[0]
            return {
                "tool_name": tc.function.name,
                "params": json.loads(tc.function.arguments),
            }

        # Model returned structured JSON in plain text
        try:
            content = json.loads(msg.content or "{}")
            if content.get("error") == "out_of_scope":
                return {
                    "error": "out_of_scope",
                    "reason": content.get("reason", "Request out of scope"),
                }
        except json.JSONDecodeError:
            pass

        return {
            "error": "no_tool_selected",
            "reason": msg.content or "Model returned no tool call",
        }

    except Exception as e:
        print("\n=== OPENAI ERROR ===")
        print(str(e))
        print("=== END OPENAI ERROR ===\n")

        return {
            "error": "llm_failure",
            "reason": str(e),
        }


async def summarise_results(nmap_findings: dict) -> str:
    """
    Deterministic Python summary.
    Generalized for port scans, service detection, OS detection, and host discovery.
    No LLM call here.
    """
    command = str(nmap_findings.get("scan_type", "")).lower()
    hosts = nmap_findings.get("hosts", [])
    total_up = nmap_findings.get("total_hosts_up", 0)
    total_down = nmap_findings.get("total_hosts_down", 0)

    if not hosts:
        if "-sn" in command:
            return (
                f"Host discovery completed. {total_up} host(s) are up and "
                f"{total_down} host(s) are down."
            )
        return "Scan completed. No hosts were found in the parsed results."

    host = hosts[0]
    address = host.get("address", "unknown target")
    status = host.get("status", "unknown")
    ports = host.get("ports", [])
    os_info = host.get("os")

    # Host discovery
    if "-sn" in command:
        return (
            f"Host discovery completed. Host {address} is {status}. "
            f"Total hosts up: {total_up}. Total hosts down: {total_down}."
        )

    # OS detection
    if " -o " in f" {command} ":
        if os_info:
            return (
                f"OS detection scan completed. Host {address} is {status}. "
                f"The scan returned operating system fingerprint information."
            )
        return (
            f"OS detection scan completed. Host {address} is {status}. "
            f"No reliable operating system match was returned in the parsed results."
        )

    # Service detection
    if "-sv" in command:
        if not ports:
            return (
                f"Service detection scan completed. Host {address} is {status}. "
                f"No service details were returned."
            )

        open_services = []
        for p in ports:
            if p.get("state") == "open":
                service = p.get("service", "unknown service")
                product = p.get("product", "")
                if product:
                    open_services.append(f"port {p['port']} ({service}, {product})")
                else:
                    open_services.append(f"port {p['port']} ({service})")

        if open_services:
            return (
                f"Service detection scan completed. Host {address} is {status}. "
                f"Detected open services on {', '.join(open_services)}."
            )

        return (
            f"Service detection scan completed. Host {address} is {status}. "
            f"No open services were identified in the scanned ports."
        )

    # General port scan
    if not ports:
        return f"Scan completed. Host {address} is {status}. No port results were returned."

    open_ports = [str(p["port"]) for p in ports if p.get("state") == "open"]
    closed_ports = [str(p["port"]) for p in ports if p.get("state") == "closed"]
    filtered_ports = [str(p["port"]) for p in ports if p.get("state") == "filtered"]

    if open_ports:
        return (
            f"Port scan completed. Host {address} is {status}. "
            f"Open ports found: {', '.join(open_ports)}."
        )

    if closed_ports and not open_ports:
        return (
            f"Port scan completed. Host {address} is {status}. "
            f"Ports {', '.join(closed_ports)} were scanned and all were closed."
        )

    if filtered_ports and not open_ports and not closed_ports:
        return (
            f"Port scan completed. Host {address} is {status}. "
            f"Ports {', '.join(filtered_ports)} were filtered."
        )

    return f"Scan completed. Host {address} is {status}. Results were returned."