import os
import tempfile
import pytest

from seccontrol_sentinel.scanner.signatures import calculate_sha256, KNOWN_MALICIOUS_HASHES
from seccontrol_sentinel.scanner.heuristics import analyze_heuristics
from seccontrol_sentinel.scanner.engine import MalwareScanner
from seccontrol_sentinel.monitor.fim import FileIntegrityMonitor
from seccontrol_sentinel.compliance.nis2 import NIS2Evaluator

def test_signature_calculation():
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("SecControl Sentinel Test Data")
        temp_name = f.name
    try:
        sha = calculate_sha256(temp_name)
        assert len(sha) == 64
    finally:
        os.remove(temp_name)

def test_heuristic_detection_php_eval():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".php", delete=False) as f:
        f.write("<?php eval(base64_decode('payload')); ?>")
        temp_name = f.name
    try:
        findings = analyze_heuristics(temp_name)
        assert len(findings) > 0
        assert findings[0][0] == "PHP Obfuscated Exec"
    finally:
        os.remove(temp_name)

def test_file_integrity_monitor():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Initial content")

        fim = FileIntegrityMonitor([temp_dir])
        baseline_count = fim.build_baseline()
        assert baseline_count >= 1

        # Check clean
        assert len(fim.check_integrity()) == 0

        # Modify file
        with open(test_file, "w") as f:
            f.write("Tampered content")

        alerts = fim.check_integrity()
        assert len(alerts) == 1
        assert alerts[0]["event"] == "FILE_MODIFIED"

def test_nis2_evaluator():
    evaluator = NIS2Evaluator()
    # Clean posture
    report = evaluator.evaluate_compliance([], [], [], {"dmarc_policy": "reject", "spf_status": "present"})
    assert report["score"] == 100
    assert report["grade"] == "A"
    assert report["nis2_aligned"] is True

    # Poor posture with FTP 21 and DMARC missing
    poor_report = evaluator.evaluate_compliance([], [], [{"port": 21}], {"dmarc_policy": "missing"})
    assert poor_report["score"] < 70
    assert poor_report["nis2_aligned"] is False
