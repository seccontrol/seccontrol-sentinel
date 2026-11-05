import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional

from seccontrol_sentinel.scanner.signatures import calculate_sha256, KNOWN_MALICIOUS_HASHES
from seccontrol_sentinel.scanner.heuristics import analyze_heuristics

class ScanResult:
    def __init__(self, filepath: str, threat_name: str, detection_type: str, severity: str, details: str):
        self.filepath = filepath
        self.threat_name = threat_name
        self.detection_type = detection_type
        self.severity = severity
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "threat_name": self.threat_name,
            "detection_type": self.detection_type,
            "severity": self.severity,
            "details": self.details
        }

class MalwareScanner:
    def __init__(self, max_workers: int = 4, max_file_size_mb: int = 50):
        self.max_workers = max_workers
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

    def scan_file(self, filepath: str) -> Optional[ScanResult]:
        try:
            stat = os.stat(filepath)
            if stat.st_size > self.max_file_size_bytes:
                return None

            # 1. Signature Check
            sha256 = calculate_sha256(filepath)
            if sha256 in KNOWN_MALICIOUS_HASHES:
                threat = KNOWN_MALICIOUS_HASHES[sha256]
                return ScanResult(
                    filepath=filepath,
                    threat_name=threat,
                    detection_type="SHA-256 Signature Match",
                    severity="Critical",
                    details=f"Identified known malicious payload hash: {sha256}"
                )

            # 2. Heuristic Pattern Check
            heuristics = analyze_heuristics(filepath)
            if heuristics:
                rule, sev = heuristics[0]
                return ScanResult(
                    filepath=filepath,
                    threat_name=f"Heuristic.{rule.replace(' ', '_')}",
                    detection_type="Behavioral Pattern",
                    severity=sev,
                    details=f"Matched suspicious pattern rule: '{rule}'"
                )

            return None
        except Exception:
            return None

    def scan_directory(self, target_dir: str, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[ScanResult]:
        files_to_scan = []
        for root, _, files in os.walk(target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                files_to_scan.append(full_path)

        total_files = len(files_to_scan)
        findings = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files_to_scan}
            completed = 0
            for future in as_completed(future_to_file):
                completed += 1
                if progress_callback:
                    progress_callback(completed, total_files)
                result = future.result()
                if result:
                    findings.append(result)

        return findings
