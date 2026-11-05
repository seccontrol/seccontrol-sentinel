import socket
import psutil
from typing import List, Dict, Any, Optional

try:
    import dns.resolver
except ImportError:
    dns = None

CLEARTEXT_INSECURE_PORTS = {
    21: ("FTP (RFC 959)", "Cleartext credentials and data transmission. Exposed to sniffing and MITM."),
    23: ("Telnet", "Unencrypted remote shell protocol."),
    25: ("SMTP (Plain)", "Cleartext email transmission on default port."),
    80: ("HTTP (Cleartext)", "Unencrypted web traffic without mandatory TLS/HTTPS redirect."),
    3389: ("RDP Direct", "Remote Desktop exposed directly to the network without VPN/Zero Trust.")
}

class PerimeterWatchdog:
    def __init__(self):
        pass

    def scan_listening_services(self) -> List[Dict[str, Any]]:
        """Audits all listening TCP sockets on the host for cleartext or high-risk services."""
        findings = []
        try:
            connections = psutil.net_connections(kind='tcp')
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    ip = conn.laddr.ip
                    port = conn.laddr.port

                    if port in CLEARTEXT_INSECURE_PORTS:
                        svc_name, risk_desc = CLEARTEXT_INSECURE_PORTS[port]
                        severity = "Critical" if port in (21, 23) else "High"
                        findings.append({
                            "port": port,
                            "ip": ip,
                            "service": svc_name,
                            "severity": severity,
                            "risk": risk_desc,
                            "remediation": f"Disable port {port} or enforce TLS (e.g., migrate to SFTP/SSH for port 21, HTTPS for port 80)."
                        })
        except (psutil.AccessDenied, PermissionError):
            pass

        return findings

    def check_domain_dns_hygiene(self, domain: str) -> Dict[str, Any]:
        """Audits the domain's SPF and DMARC posture to prevent spoofing and BEC."""
        if not dns:
            return {"error": "dnspython package not installed"}

        results = {
            "domain": domain,
            "spf_status": "missing",
            "dmarc_policy": "missing",
            "risk_score": 0,
            "findings": []
        }

        # Check SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    results["spf_status"] = "present"
                    break
        except Exception:
            results["spf_status"] = "missing"

        if results["spf_status"] == "missing":
            results["risk_score"] += 30
            results["findings"].append("Missing SPF record: Anyone can forge emails appearing from this domain.")

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=DMARC1" in txt:
                    if "p=reject" in txt:
                        results["dmarc_policy"] = "reject"
                    elif "p=quarantine" in txt:
                        results["dmarc_policy"] = "quarantine"
                    else:
                        results["dmarc_policy"] = "none"
                    break
        except Exception:
            results["dmarc_policy"] = "missing"

        if results["dmarc_policy"] in ("missing", "none"):
            results["risk_score"] += 45
            results["findings"].append(f"Insecure DMARC policy (p={results['dmarc_policy']}): Domain vulnerable to BEC spoofing.")

        return results
