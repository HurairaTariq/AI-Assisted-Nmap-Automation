"""
Multi-stage validation engine.
Receives the MCP tool call from GPT-4.1 and runs five sequential checks.
Any failure returns a structured rejection — Docker is never touched.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional, List
from app.config import settings


@dataclass
class ValidationResult:
    passed: bool
    reason: Optional[str] = None
    nmap_command: Optional[str] = None


def _parse_port_count(port_spec: str) -> int:
    """Count individual ports in a spec like '22,80,443' or '80-1024'."""
    total = 0
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            total += int(hi) - int(lo) + 1
        else:
            total += 1
    return total


def _is_valid_target(target: str) -> bool:
    """Accept IPs, CIDRs, and basic hostnames/FQDNs."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(hostname_re.match(target))


def _get_cidr_prefix(target: str) -> Optional[int]:
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.prefixlen
    except ValueError:
        return None


# CHECK 1 — Target allowlist

def check_allowlist(target: str, user_allowlist: List[str]) -> ValidationResult:
    if not _is_valid_target(target):
        return ValidationResult(False, f"Target '{target}' is not a valid IP, CIDR, or hostname.")

    # RFC 1918 ranges are auto-permitted (lab environments)
    try:
        net = ipaddress.ip_network(target, strict=False)
        for private in [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]:
            if net.subnet_of(private):
                return ValidationResult(True)
    except ValueError:
        pass

    def clean_value(v: str) -> str:
        return str(v).strip().strip('"').strip("'").lower()

    target_clean = clean_value(target)
    allowlist_clean = [clean_value(x) for x in (user_allowlist or [])]

    print("TARGET CLEAN:", target_clean)
    print("ALLOWLIST CLEAN:", allowlist_clean)

    if not allowlist_clean or target_clean not in allowlist_clean:
        return ValidationResult(
            False,
            f"Target '{target}' is not on your registered allowlist. "
            "Register it in your account settings before scanning."
        )

    return ValidationResult(True)



# CHECK 2 — Port range

def check_ports(ports: str) -> ValidationResult:
    try:
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                if not (1 <= int(lo) <= 65535 and 1 <= int(hi) <= 65535):
                    raise ValueError
                if int(lo) > int(hi):
                    raise ValueError
            else:
                if not (1 <= int(part) <= 65535):
                    raise ValueError
    except (ValueError, TypeError):
        return ValidationResult(False, f"Port specification '{ports}' contains invalid values.")

    count = _parse_port_count(ports)
    if count > settings.MAX_PORTS_PER_REQUEST:
        return ValidationResult(
            False,
            f"Port count {count} exceeds the maximum of {settings.MAX_PORTS_PER_REQUEST} per request."
        )
    return ValidationResult(True)


# CHECK 3 — Blocked flags

def check_flags(params: dict) -> ValidationResult:
    param_str = " ".join(str(v) for v in params.values()).lower()
    for blocked in settings.BLOCKED_FLAGS:
        if blocked.lower() in param_str:
            return ValidationResult(
                False,
                f"Blocked parameter detected: '{blocked}'. "
                "Fragmentation, spoofing, decoy, proxy, and exploit flags are not permitted."
            )
    return ValidationResult(True)



# CHECK 4 — CIDR scope (host_discovery only)

def check_cidr_scope(target: str) -> ValidationResult:
    prefix = _get_cidr_prefix(target)
    if prefix is not None and prefix < settings.MAX_CIDR_PREFIX:
        return ValidationResult(
            False,
            f"CIDR /{prefix} exceeds the maximum permitted range of /{settings.MAX_CIDR_PREFIX}. "
            "Please use a more specific subnet."
        )
    return ValidationResult(True)



# CHECK 5 — Timing template

def check_timing(timing: Optional[str]) -> ValidationResult:
    if timing and timing not in settings.ALLOWED_TIMING_TEMPLATES:
        return ValidationResult(
            False,
            f"Timing template '{timing}' is not permitted. "
            f"Allowed values: {', '.join(settings.ALLOWED_TIMING_TEMPLATES)}."
        )
    return ValidationResult(True)



# CHECK 6 — NSE script whitelist

def check_scripts(scripts: List[str]) -> ValidationResult:
    for s in scripts:
        if s not in settings.ALLOWED_NSE_SCRIPTS:
            return ValidationResult(
                False,
                f"NSE script '{s}' is not on the permitted whitelist. "
                "Only informational, non-intrusive scripts are allowed."
            )
    return ValidationResult(True)



# Command builders

def _build_command(tool: str, params: dict) -> str:
    t = params.get("target", "")
    p = params.get("ports", "")
    timing = params.get("timing", "T3")

    if tool == "port_scan":
        flag = "-sS" if params.get("scan_type") == "syn" else "-sT"
        return f"nmap {flag} -p {p} -{timing} -oX - {t}"

    if tool == "service_detect":
        intensity = params.get("intensity", 5)
        return f"nmap -sV --version-intensity {intensity} -p {p} -oX - {t}"

    if tool == "os_detect":
        return f"nmap -O -oX - {t}"

    if tool == "vuln_scan":
        scripts = ",".join(params.get("scripts", []))
        return f"nmap --script {scripts} -oX - {t}"

    if tool == "host_discovery":
        return f"nmap -sn -oX - {t}"

    raise ValueError(f"Unknown tool: {tool}")



# Main entry point

def validate(tool_name: str, params: dict, user_allowlist: List[str]) -> ValidationResult:
    """
    Run all applicable validation checks for the given tool call.
    Returns immediately on first failure (fail-fast).
    """
    target = params.get("target", "")

    # 1. Allowlist
    r = check_allowlist(target, user_allowlist)
    if not r.passed:
        return r

    # 2. Ports (where applicable)
    if "ports" in params:
        r = check_ports(params["ports"])
        if not r.passed:
            return r

    # 3. Blocked flags
    r = check_flags(params)
    if not r.passed:
        return r

    # 4. CIDR scope (host_discovery)
    if tool_name == "host_discovery":
        r = check_cidr_scope(target)
        if not r.passed:
            return r

    # 5. Timing template
    r = check_timing(params.get("timing"))
    if not r.passed:
        return r

    # 6. NSE script whitelist (vuln_scan)
    if tool_name == "vuln_scan":
        r = check_scripts(params.get("scripts", []))
        if not r.passed:
            return r

    # All checks passed — build the sanitised command
    cmd = _build_command(tool_name, params)
    return ValidationResult(passed=True, nmap_command=cmd)