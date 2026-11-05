<p align="center">
  <img src="https://raw.githubusercontent.com/seccontrol/seccontrol-sentinel/main/docs/assets/banner.svg" alt="SecControl Sentinel Banner" width="100%" onerror="this.style.display='none'"/>
</p>

# 🛡️ SecControl Sentinel

[![CI Workflow](https://github.com/seccontrol/seccontrol-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/seccontrol/seccontrol-sentinel/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![NIS2 Compliant](https://img.shields.io/badge/NIS2%20Cyber%20Hygiene-Art.%2021%20Ready-emerald.svg)](https://seccontrol.it)
[![SOC Integration](https://img.shields.io/badge/SOC%20SecControl-Connected-rose.svg)](https://seccontrol.it)

**SecControl Sentinel** is a lightweight, high-performance, open-source endpoint detection, behavioral antivirus, and perimeter monitoring watchdog (EDR / EASM) designed for Linux, Windows, and macOS enterprise environments.

Developed by **[SecControl SOC & Threat Intelligence](https://seccontrol.it)**, Sentinel bridges the gap between active host protection, real-time file integrity monitoring (FIM), and external perimeter exposure auditing (detecting unencrypted RFC 959 FTP 21, Telnet, and DNS spoofing risks), providing turnkey compliance with the European **NIS2 Directive (D.Lgs. 138/2024)**.

---

## ⚡ Key Capabilities

### 1. 🦠 Behavioral Antivirus & Malware Engine
* **Multi-Threaded Signature Scanner**: Instant verification of SHA-256 and MD5 hashes against known trojans, ransomware binaries, and cryptocurrency miners.
* **Heuristic Pattern Matcher**: Detects obfuscated webshells (`eval(base64_decode)`, Cobalt Strike stagers, reverse shell one-liners, PowerShell unconstrained execution).
* **Ransomware Burst Detection**: Monitors rapid mass file entropy shifts and unauthorized directory traversal typical of lockfile campaigns.

### 2. 👁️ Real-Time File Integrity Monitor (FIM)
* Cryptographic baseline hashing of critical system directories (`/etc/`, `/usr/bin/`, `/var/www/`, `C:\Windows\System32\`).
* Real-time alerting upon unauthorized file drops, binary modifications, or privilege elevation attempts.

### 3. 🌐 Perimeter & Exposure Watchdog (EASM)
* **RFC 959 Cleartext FTP Detector**: Alerts immediately if port 21/TCP is listening without TLS enforcement, preventing unencrypted document and credential exposure.
* **Insecure Service Sentinel**: Flags open Telnet (23), legacy unencrypted SMTP (25), and directly exposed database/RDP ports.
* **DNS Cyber Hygiene Checker**: Evaluates authoritative domain records for SPF (`RFC 7208`) and DMARC (`RFC 7489`) enforcement to stop Business Email Compromise (BEC) and spoofing.

### 4. 📜 NIS2 & Cyber Hygiene Telemetry Exporter
* Generates audit-ready Markdown and JSON telemetry maps directly aligned with **Art. 21 of D.Lgs. 138/2024** (Italian NIS2 transposition).
* Evaluates host posture score (Grado A, B, C, D) and outputs remediation playbooks for sysadmins and DevOps engineers.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/seccontrol/seccontrol-sentinel.git
cd seccontrol-sentinel

# Install dependencies and package
pip install -r requirements.txt
pip install -e .
```

---

## 🛠️ Command-Line Usage

SecControl Sentinel provides a clean, interactive CLI powered by rich formatting:

### 1. Full Malware & Antivirus Scan
Scan any directory or file tree for suspicious indicators, webshells, and known malicious hashes:
```bash
seccontrol-sentinel scan /var/www/html
```

### 2. Perimeter & Listening Port Audit
Audit local interfaces for insecure cleartext protocols (e.g. RFC 959 cleartext FTP, Telnet) and evaluate perimetric risk:
```bash
seccontrol-sentinel audit-perimeter
```

### 3. Real-Time File Integrity Monitor (FIM)
Create a cryptographic baseline and watch for modifications in real-time:
```bash
seccontrol-sentinel monitor --path /etc --interval 5
```

### 4. NIS2 Compliance Report Generation
Evaluate system cyber hygiene and produce a compliance report:
```bash
seccontrol-sentinel report-nis2 --domain company.it --output nis2_audit.json
```

---

## 🏗️ Architecture

```mermaid
flowchart TD
    subgraph Host_Environment ["Host Environment"]
        FS[File System & System Binaries]
        PROC[Active Processes & Memory]
        NET[Network Sockets & Open Ports]
    end

    subgraph Sentinel_Core ["SecControl Sentinel Core"]
        SCN["Antivirus & Signature Scanner"]
        HEUR["Heuristic Pattern Matcher"]
        FIM["File Integrity Monitor (SHA-256)"]
        PERIM["Perimeter & RFC 959 Watchdog"]
        NIS2["NIS2 Posture Evaluator"]
    end

    subgraph Outputs ["SecControl Security Telemetry"]
        CLI[Terminal Dashboard]
        JSON[Audit JSON Logs]
        SOC["SecControl SOC API (seccontrol.it)"]
    end

    FS --> SCN
    FS --> FIM
    PROC --> HEUR
    NET --> PERIM

    SCN --> NIS2
    HEUR --> NIS2
    FIM --> NIS2
    PERIM --> NIS2

    NIS2 --> CLI
    NIS2 --> JSON
    NIS2 -.-> SOC
```

---

## 🔒 Security & Responsible Disclosure

SecControl Sentinel is maintained by the **SecControl SOC & Threat Intelligence Unit**.
If you discover a security vulnerability or wish to report indicators of compromise (IoC), please consult our [Security Policy](SECURITY.md) or contact us directly at:
📧 **assistenza@seccontrol.it** 

---

## 📄 License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for details.
Copyright © 2026 [SecControl Italia](https://seccontrol.it). All rights reserved.
