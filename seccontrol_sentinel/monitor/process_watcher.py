import psutil
from typing import List, Dict, Any

SUSPICIOUS_PROCESS_NAMES = {
    "nc", "ncat", "netcat", "mimikatz", "chisel", "ngrok", "xmrig", "stratum", "c99", "r57"
}

class ProcessWatcher:
    def __init__(self):
        pass

    def inspect_active_processes(self) -> List[Dict[str, Any]]:
        """Audits all active processes for suspicious commandlines, unlinked binaries, and known miners/backdoors."""
        anomalies = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'cpu_percent']):
            try:
                info = proc.info
                name = (info.get('name') or '').lower()
                cmdline_list = info.get('cmdline') or []
                cmdline = ' '.join(cmdline_list).lower()

                # Check process name against known hacker tools / miners
                if name in SUSPICIOUS_PROCESS_NAMES:
                    anomalies.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "severity": "Critical",
                        "reason": f"Active execution of known dual-use/offensive binary: '{name}'",
                        "cmdline": cmdline[:200]
                    })
                    continue

                # Check for suspicious commandline patterns
                if "eval(base64" in cmdline or "downloadstring" in cmdline or "/dev/tcp/" in cmdline:
                    anomalies.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "severity": "Critical",
                        "reason": "Process commandline contains in-memory payload download or reverse shell",
                        "cmdline": cmdline[:200]
                    })
                    continue

                if "stratum+tcp://" in cmdline or "pool.minexmr.com" in cmdline:
                    anomalies.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "severity": "Critical",
                        "reason": "Crypto-jacking miner stratum connection detected",
                        "cmdline": cmdline[:200]
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return anomalies
