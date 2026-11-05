import os
import time
from typing import Dict, Any, List
from seccontrol_sentinel.scanner.signatures import calculate_sha256

class FileIntegrityMonitor:
    def __init__(self, watch_paths: List[str]):
        self.watch_paths = watch_paths
        self.baseline: Dict[str, Dict[str, Any]] = {}

    def build_baseline(self) -> int:
        """Takes a cryptographic snapshot of watched directories."""
        self.baseline.clear()
        count = 0
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                self._record_file(path)
                count += 1
            else:
                for root, _, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        self._record_file(full_path)
                        count += 1
        return count

    def _record_file(self, full_path: str):
        try:
            stat = os.stat(full_path)
            self.baseline[full_path] = {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "sha256": calculate_sha256(full_path)
            }
        except (PermissionError, FileNotFoundError, OSError):
            pass

    def check_integrity(self) -> List[Dict[str, Any]]:
        """Compares the current filesystem state against the baseline and returns diff alerts."""
        alerts = []
        current_files = set()

        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                files_to_check = [path]
            else:
                files_to_check = []
                for root, _, files in os.walk(path):
                    for file in files:
                        files_to_check.append(os.path.join(root, file))

            for full_path in files_to_check:
                current_files.add(full_path)
                if full_path not in self.baseline:
                    alerts.append({
                        "event": "FILE_CREATED",
                        "path": full_path,
                        "severity": "Warning",
                        "timestamp": time.time(),
                        "details": "New file dropped into watched directory"
                    })
                else:
                    try:
                        stat = os.stat(full_path)
                        base = self.baseline[full_path]
                        if stat.st_mtime != base["mtime"] or stat.st_size != base["size"]:
                            current_hash = calculate_sha256(full_path)
                            if current_hash != base["sha256"]:
                                alerts.append({
                                    "event": "FILE_MODIFIED",
                                    "path": full_path,
                                    "severity": "High",
                                    "timestamp": time.time(),
                                    "details": f"Cryptographic integrity altered. Old: {base['sha256'][:10]}... New: {current_hash[:10]}..."
                                })
                    except (PermissionError, FileNotFoundError, OSError):
                        pass

        # Check for deleted files
        for baseline_path in self.baseline:
            if baseline_path not in current_files and not os.path.exists(baseline_path):
                alerts.append({
                    "event": "FILE_DELETED",
                    "path": baseline_path,
                    "severity": "High",
                    "timestamp": time.time(),
                    "details": "Critical file removed from filesystem"
                })

        return alerts
