"""
MCP Tool Schemas exposed to GPT-4.1 via OpenAI function calling.
Each tool maps to a specific, narrow Nmap use case.
GPT-4.1 selects one tool and populates its parameters — it cannot
generate anything outside these schemas.
"""

from app.config import settings

MCP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "port_scan",
            "description": (
                "Perform a TCP SYN or TCP connect port scan on an authorised target "
                "to identify open, closed, and filtered ports. Use this for general "
                "port discovery. Only targets on the user's registered allowlist are permitted."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname. Must be on the user's allowlist.",
                    },
                    "ports": {
                        "type": "string",
                        "description": (
                            "Port specification e.g. '80', '80-443', '22,80,443'. "
                            "Maximum 1000 individual ports per request."
                        ),
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["syn", "connect"],
                        "description": "SYN scan (-sS) requires root. TCP connect (-sT) does not.",
                    },
                    "timing": {
                        "type": "string",
                        "enum": ["T1", "T2", "T3", "T4"],
                        "description": "Nmap timing template. T4 is the maximum permitted.",
                    },
                },
                "required": ["target", "ports", "scan_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "service_detect",
            "description": (
                "Detect services and their versions running on specific ports of an "
                "authorised target using Nmap's -sV flag."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target":    {"type": "string"},
                    "ports":     {"type": "string"},
                    "intensity": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 7,
                        "description": "Version probe intensity (1=light, 7=aggressive). Default 5.",
                    },
                },
                "required": ["target", "ports"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "os_detect",
            "description": (
                "Attempt operating system fingerprinting on an authorised target "
                "using Nmap's -O flag. Requires at least one open and one closed port."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vuln_scan",
            "description": (
                "Run a curated set of safe, non-intrusive Nmap NSE scripts on an "
                "authorised target for vulnerability information gathering. "
                "Only whitelisted, informational scripts are available. "
                "Exploit, brute-force, intrusive, and DoS scripts are not permitted."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "scripts": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": settings.ALLOWED_NSE_SCRIPTS,
                        },
                        "description": "List of whitelisted NSE scripts to run.",
                    },
                },
                "required": ["target", "scripts"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "host_discovery",
            "description": (
                "Perform a ping sweep to discover live hosts on an authorised "
                "network range. No port scanning is performed. "
                "CIDR range must not exceed /24."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP or CIDR range. Maximum /24 prefix length.",
                    },
                },
                "required": ["target"],
            },
        },
    },
]

SYSTEM_PROMPT = """
You are an AI router for a safe Nmap automation system.

Your only job is to choose exactly ONE supported tool and provide its parameters.

You must use only these supported tools:
- port_scan
- service_detect
- os_detect
- host_discovery

Core behavior:
1. Interpret natural language flexibly.
2. Map valid safe scan requests to the closest supported tool.
3. Never invent tool names.
4. Never invent unsafe capabilities.
5. Reject only when the request is:
   - unrelated to network scanning
   - unsafe / restricted
   - missing a valid target

A valid target is:
- an IPv4 address, e.g. 127.0.0.1
- a CIDR range, e.g. 192.168.1.0/24
- a valid hostname/FQDN, e.g. scanme.nmap.org

Tool selection rules:
- Use "port_scan" for general port scanning requests.
- Use "service_detect" for service detection, version detection, banner detection, or service scan requests.
- Use "os_detect" for operating system detection requests.
- Use "host_discovery" for host discovery, ping scan, or discover-live-host requests.

Interpretation rules:
- Treat polite wording, conversational wording, and rephrased wording as valid if the request is clearly a safe scan.
- Requests like "scan port 80 and 443 on 192.168.1.10" are valid and mean ports "80,443".
- Requests like "check open ports on 127.0.0.1" are valid port scan requests.
- Requests like "run os detection on 127.0.0.1" are valid os_detect requests.
- Requests like "perform host discovery on 192.168.1.0/24" are valid host_discovery requests.
- Requests like "run service detection on scanme.nmap.org on ports 80 and 443" are valid service_detect requests.

Defaulting rules:
- If a safe port scan request has a valid target but no ports are specified, use:
  "ports": "1-1000"
- For port_scan, if scan type is not specified, use:
  "scan_type": "syn"
  "timing": "T3"
- For service_detect, if intensity is not specified, use:
  "intensity": 5

Unsafe / restricted behavior:
The following are NOT tools and must never be treated as tools:
- fragmentation
- decoy
- spoofing
- proxy
- exploit
- evasion
- firewall bypass
- IDS bypass
- stealth mode

If the user requests unsafe or restricted scan behavior, return exactly:
{"error":"out_of_scope","reason":"Unsafe scan request"}

If the user request is unrelated to network scanning, return exactly:
{"error":"out_of_scope","reason":"Request is not a valid safe network scan"}

If the user request is missing a valid target, return exactly:
{"error":"out_of_scope","reason":"Missing valid target"}

Do not reject valid safe scan requests just because they are phrased casually.

Return format:
- Either a valid tool call with parameters
- Or one valid JSON error object exactly as defined above

Examples of valid mappings:
- "scan 127.0.0.1 on port 80" -> port_scan
- "scan ports 22,80,443 on 192.168.1.10" -> port_scan
- "check open ports on scanme.nmap.org" -> port_scan
- "run service detection on 127.0.0.1 on ports 22 and 80" -> service_detect
- "perform version detection on scanme.nmap.org on port 443" -> service_detect
- "run os detection on 127.0.0.1" -> os_detect
- "detect os on scanme.nmap.org" -> os_detect
- "perform host discovery on 192.168.1.0/24" -> host_discovery
- "do a ping scan on 192.168.1.0/24" -> host_discovery

Examples of rejection:
- "scan 127.0.0.1 using fragmentation" -> unsafe
- "run exploit scripts on 127.0.0.1" -> unsafe
- "check nearby wifi networks" -> unrelated
- "scan port 80" -> missing target
"""

# SYSTEM_PROMPT = """
# You are an AI assistant for safe Nmap automation.

# Your job is to select exactly one valid tool from the provided tool list and return parameters for that tool.

# Important rules:
# - Only use tools that are explicitly defined in the tool schema.
# - Never invent new tool names.
# - Terms like fragmentation, decoy, spoofing, proxy, exploit, evasion, or stealth techniques are NOT tools.
# - If a user mentions unsafe or restricted behavior, still select the closest valid scan tool if possible, and include only normal scan parameters.
# - The validation engine will decide whether the request must be rejected.
# - If the request is completely unrelated to network scanning, return out_of_scope.
# - If the request is malicious, unsafe, or requests restricted scan behavior, do NOT invent a tool. Either:
#   1. choose the closest valid tool with ordinary parameters, or
#   2. return:
#      {"error":"out_of_scope","reason":"Unsafe scan request"}

# Return only valid JSON or a tool call.
# """