# 🛡️ SecControl Sentinel v2.4.1

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![NIS2 Directive](https://img.shields.io/badge/NIS2%20Compliant-Art.%2021%20Ready-emerald.svg)](https://seccontrol.it)
[![ISO/IEC 27001](https://img.shields.io/badge/ISO%2F27001%3A2022-A.12%20Aligned-sky.svg)](https://seccontrol.it)
[![SOC SecControl](https://img.shields.io/badge/SOC%20SecControl-Connected-rose.svg)](https://seccontrol.it)

**SecControl Sentinel** è lo strumento aziendale autonomo e open-source di **Endpoint Detection & Response (EDR)**, **Antivirus Comportamentale** e **Perimeter Exposure Watchdog** sviluppato dalla Threat Intelligence Unit di **[SecControl Italia](https://seccontrol.it)**.

Progettato per server Linux (systemd) e Windows Server, Sentinel opera a bassissimo impatto di risorse (**17.4 MB RAM**, `<0.1% CPU`) garantendo il monitoraggio continuo dell'integrità del filesystem (FIM con crittografia SHA-256), l'audit delle porte in chiaro obsolete (**RFC 959 FTP 21**, Telnet 23) e la piena rispondenza alla **Direttiva Europea NIS2 (D.Lgs. 138/2024, Art. 21)**.

---

## 🚀 Novità v2.4.1: Dark Glassmorphic Web GUI

SecControl Sentinel integra nativamente una **GUI web interattiva** con design dark glassmorphic coerente con la suite SecControl, eseguibile localmente senza alcuna dipendenza grafica esterna pesante:

```bash
# Avvio della GUI locale (porta default 9876)
seccontrol-sentinel gui
```
Accedi immediatamente dal browser a `http://127.0.0.1:9876` per:
- Visualizzare la telemetria live del nodo e il Security Posture Grade.
- Eseguire scansioni antivirus multithread con barra di avanzamento e report delle evidenze.
- Verificare i socket di rete aperti e lo stato SPF/DMARC del dominio aziendale.
- Esportare l'attestato di conformità peritale per la Direttiva NIS2 e audit assicurativi cyber risk.

---

## ⚡ Installazione & Test in Autonomia

### 1. Clonazione del Repository Pubblico
```bash
git clone https://github.com/seccontrol/seccontrol-sentinel.git
cd seccontrol-sentinel
```

### 2. Installazione delle Dipendenze
```bash
pip install -e .
```

### 3. Esecuzione da Riga di Comando (CLI)

#### Scansione Antivirus del Filesystem:
```bash
seccontrol-sentinel scan /var/www/html --threads 8
```

#### Watchdog Perimetrale & Cyber Hygiene DNS:
```bash
seccontrol-sentinel audit-perimeter --domain tuodominio.it
```

#### Monitoraggio Real-Time FIM & Processi:
```bash
seccontrol-sentinel monitor --paths /etc /var/www --interval 5
```

#### Generazione Report di Conformità NIS2:
```bash
seccontrol-sentinel report-nis2 --domain tuodominio.it --scan-dir /var/www --output nis2-report.json
```

---

## 📜 Certificazioni & Standard Aziendali

SecControl Sentinel è ingegnerizzato secondo le migliori pratiche internazionali e supporta gli adempimenti normativi:

1. **Direttiva NIS2 (UE 2022/2555 - D.Lgs. 138/2024 Art. 21)**: Misure obbligatorie di cyber hygiene, gestione delle vulnerabilità e isolamento dei canali non cifrati.
2. **ISO/IEC 27001:2022**:
   - `Controllo A.8.7`: Protezione contro malware e software dannoso.
   - `Controllo A.8.8`: Gestione delle vulnerabilità tecniche.
   - `Controllo A.8.20`: Sicurezza delle reti e segregazione dei servizi esposti.
3. **GDPR (Regolamento UE 2016/679 - Art. 32)**: Adozione di misure tecniche preventive a tutela della riservatezza e integrità dei dati trattati.
4. **CIS Critical Security Controls v8**: Controlli 4 (Secure Configuration), 7 (Continuous Vulnerability Management) e 9 (Email & Web Protections).

---

## 🔒 Licenza & Sicurezza

Rilasciato sotto licenza [Apache 2.0](LICENSE).  
Supporto aziendale e integrazione SOC: [assistenza@seccontrol.it](mailto:assistenza@seccontrol.it) • [https://seccontrol.it](https://seccontrol.it).
