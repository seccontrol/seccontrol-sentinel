import re
from typing import List, Tuple

# Suspicious code patterns (Webshells, Remote execution, Obfuscation)
HEURISTIC_RULES: List[Tuple[str, str, str]] = [
    (
        "PHP Obfuscated Exec",
        r"(?:eval|assert|passthru|shell_exec|system)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(",
        "High"
    ),
    (
        "Bash Reverse Shell",
        r"bash\s+-i\s+>&?\s+/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+",
        "Critical"
    ),
    (
        "Python Interactive Reverse Shell",
        r"socket\.socket\s*\(.*?\)\.connect\s*\(.*?\)\s*;.*?os\.dup2",
        "Critical"
    ),
    (
        "PowerShell Encoded Execution",
        r"powershell(?:\.exe)?\s+(?:-[eE](?:nc(?:odedcommand)?)?)\s+[A-Za-z0-9+/=]{20,}",
        "High"
    ),
    (
        "Hidden Shadow Rootkit Dropper",
        r"(?:curl|wget)\s+-(?:fs?SL|qO-)\s+https?://[^\s|]+\s*\|\s*(?:ba)?sh",
        "High"
    )
]

def analyze_heuristics(filepath: str, max_read_bytes: int = 1048576) -> List[Tuple[str, str]]:
    """Analyzes text/script files against heuristic suspicious patterns."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(max_read_bytes)
            for rule_name, pattern, severity in HEURISTIC_RULES:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append((rule_name, severity))
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return findings
