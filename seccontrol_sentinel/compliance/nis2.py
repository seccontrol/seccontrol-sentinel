from typing import Dict, Any, List

class NIS2Evaluator:
    def __init__(self):
        pass

    def evaluate_compliance(
        self,
        antivirus_findings: List[Any],
        fim_alerts: List[Any],
        perimeter_findings: List[Any],
        dns_posture: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculates an enterprise cyber hygiene grade aligned with NIS2 Art. 21 (D.Lgs. 138/2024)."""
        score = 100
        critical_issues = []
        checks = []

        # 1. Endpoint Integrity & Malware (Art. 21 comma 2 lett. e)
        if antivirus_findings:
            score -= 40
            critical_issues.append(f"Active malware/webshell detected ({len(antivirus_findings)} items).")
            checks.append({"control": "Endpoint Protection (EDR)", "status": "FAIL", "severity": "Critical"})
        else:
            checks.append({"control": "Endpoint Protection (EDR)", "status": "PASS", "severity": "Good"})

        # 2. File Integrity (Art. 21 comma 2 lett. b)
        if fim_alerts:
            score -= 20
            critical_issues.append(f"Unauthorized filesystem modifications detected ({len(fim_alerts)} alerts).")
            checks.append({"control": "File Integrity Monitoring (FIM)", "status": "FAIL", "severity": "Warning"})
        else:
            checks.append({"control": "File Integrity Monitoring (FIM)", "status": "PASS", "severity": "Good"})

        # 3. Network Hygiene & Cleartext protocols (Art. 21 comma 2 lett. h)
        ftp_found = any(f.get("port") == 21 for f in perimeter_findings)
        if ftp_found:
            score -= 30
            critical_issues.append("RFC 959 Cleartext FTP service exposed on port 21 without mandatory TLS enforcement.")
            checks.append({"control": "Perimeter Cryptography (RFC 959 check)", "status": "FAIL", "severity": "Critical"})
        else:
            checks.append({"control": "Perimeter Cryptography (RFC 959 check)", "status": "PASS", "severity": "Good"})

        # 4. Identity & Anti-Spoofing (Art. 21 comma 2 lett. j)
        dmarc = dns_posture.get("dmarc_policy", "missing")
        if dmarc in ("missing", "none"):
            score -= 20
            critical_issues.append(f"Domain vulnerable to identity impersonation (DMARC policy: {dmarc}).")
            checks.append({"control": "Anti-Spoofing & DMARC (RFC 7489)", "status": "FAIL", "severity": "High"})
        else:
            checks.append({"control": "Anti-Spoofing & DMARC (RFC 7489)", "status": "PASS", "severity": "Good"})

        score = max(0, min(100, score))
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"

        return {
            "score": score,
            "grade": grade,
            "nis2_aligned": grade in ("A", "B"),
            "critical_issues": critical_issues,
            "controls_breakdown": checks,
            "framework": "Direttiva UE 2022/2555 (NIS2) - D.Lgs. 138/2024 Art. 21"
        }
