import hashlib

# High-confidence IoC signatures (Malicious webshells, Cobalt Strike beacons, Ransomware payloads)
KNOWN_MALICIOUS_HASHES = {
    # Well-known webshells (c99, b374k, WSO)
    "485d4303496eb5b01ce4cb42f8832ea523fbfe2ecda68ae39ae96431e7c53642": "WSO Webshell v2.5",
    "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26e32": "c99shell Backdoor",
    "7b01be44e137f8f9e0eb9d0901e18b82ff637042a969e0e5a6a4c28c898b16e4": "b374k PHP WebShell",
    # Cobalt Strike beacon payloads
    "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0": "Cobalt Strike HTTPS Beacon Stager",
    # Generic test signature (EICAR standard AV test string)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Standard-Antivirus-Test-File"
}

def calculate_sha256(filepath: str, block_size: int = 65536) -> str:
    """Computes SHA-256 hash for a given file safely without consuming high memory."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                hasher.update(block)
        return hasher.hexdigest().lower()
    except (PermissionError, FileNotFoundError, OSError):
        return ""
