"""
Parses Nmap XML output using python-libnmap into a clean structured dict
that is passed back to the user and stored in the audit log.
"""

from libnmap.parser import NmapParser, NmapParserException
from typing import Optional


def parse_nmap_xml(xml: str) -> Optional[dict]:
    """
    Returns a structured findings dict or None if parsing fails.
    """
    if not xml:
        return None

    try:
        report = NmapParser.parse_fromstring(xml)
    except NmapParserException:
        return None

    hosts_out = []
    for host in report.hosts:
        host_entry = {
            "address":  host.address,
            "status":   host.status,
            "hostnames": host.hostnames,
            "os": None,
            "ports": [],
        }

        # OS detection results
        if host.os_fingerprinted and host.os.osmatch():
            best = host.os.osmatch()[0]

            if isinstance(best, dict):
                host_entry["os"] = {
                    "name": best.get("name"),
                    "accuracy": best.get("accuracy"),
                    "cpe": best.get("cpe", []),
                }
            else:
                host_entry["os"] = {
                    "name": str(best),
                    "accuracy": None,
                    "cpe": [],
                }

        # Open ports
        for svc in host.services:
            port_entry = {
                "port":     svc.port,
                "protocol": svc.protocol,
                "state":    svc.state,
                "service":  svc.service,
                "product":  svc.banner,
                "scripts":  {},
            }
            # NSE script results
            for script_id, output in svc.scripts_results:
                port_entry["scripts"][script_id] = output

            host_entry["ports"].append(port_entry)

        hosts_out.append(host_entry)

    return {
        "scan_type":   report.commandline,
        "start_time":  report.started,
        "end_time":    report.endtime,
        "elapsed_sec": report.elapsed,
        "hosts":       hosts_out,
        "total_hosts_up":   report.hosts_up,
        "total_hosts_down": report.hosts_down,
    }