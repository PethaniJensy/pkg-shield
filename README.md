# 🛡️ Pkg-Shield (SafePip)

**An AI-Powered Active Firewall for Python Supply Chain Defense**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🛑 The Problem
Attackers are increasingly targeting the software supply chain by publishing malicious packages to PyPI (via typosquatting, dependency confusion, or hijacked accounts). Standard tools like `pip-audit` only check databases of *known* CVEs after the fact. **If a zero-day malicious package is published today, `pip` will happily install it and execute its payload.**

## 💡 Our Solution
**Pkg-Shield** intercepts `pip install` commands **before** installation occurs. It extracts static features via AST, detonates the package inside an isolated Docker sandbox, and fuses 112 telemetry features into a Random Forest Machine Learning model to evaluate the threat in real-time.

---

## 🏗️ System Architecture

Pkg-Shield relies on a robust 9-component hybrid pipeline:

```text
 Developer Terminal (pip install <pkg>)
                   │
                   ▼
 1. CLI Interceptor (Safe Download & Hash)
                   │
                   ▼
 2. Persistent SQLite Hash Database (TTL Caching)
                   │
                   ▼ (Cache Miss)
 3. Tier-1: Static AST Engine (37 Features extracted)
                   │
                   ├──────────────────────── (Fast Block if Score >= 0.85)
                   ▼
 4. Hardened Docker Sandbox Detonation (30s Guard)
    • Phase A: pip install
    • Phase B: python import
                   │
                   ▼
 5. Feature Fusion Matrix (112 Total Features)
                   │
                   ▼
 6. Random Forest ML Classifier (Risk Score 0.0 - 1.0)
                   │
                   ▼
 7. XAI Engine (Explainable AI natural language generation)
                   │
                   ▼
 8. Interactive Policy Gate (Zone 1/2/3 Actions)
```

### 🚦 Decision Zones
- **Zone 1 (Score < 0.30):** AUTO-ALLOW. Installs quietly.
- **Zone 2 (0.30 ≤ Score < 0.75):** SUSPICIOUS. Interactive prompt with audit log.
- **Zone 3 (Score ≥ 0.75):** CRITICAL THREAT. Hard block. Installation prohibited.

---

## ⚙️ Installation & Setup

### Prerequisites
- Ubuntu / Linux environment
- Python 3.11+
- Docker (must be running and accessible without `sudo`)

### 1. Clone the Repository
```bash
git clone https://github.com/PethaniJensy/pkg-shield.git
cd pkg-shield
```

### 2. Set up the Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
*(Ensure `scikit-learn`, `pandas`, `numpy`, `joblib`, and `rich` are installed).*

### 3. Initialize the Sandbox
```bash
# Build the Docker image used for dynamic detonation
cd dynamic_analyzer
docker build -t pkg-shield-sandbox -f Dockerfile.sandbox .
cd ..
```

---

## 🚀 Usage

Use `safepip.py` exactly as you would use standard `pip`.

```bash
# Install a safe package
python3 cli/safepip.py install pytz

# Install a package that triggers the security gate
python3 cli/safepip.py install requests
```

### Example Output
When a threat is detected, the terminal UI provides an immediate Explainable AI (XAI) report and blocks the installation:

```text
╭──────────────────────────────────────────────────────────────────────────────╮
│          🛡️  SafePip v2.0 Security Report: CRITICAL THREAT BLOCKED           │
╰──────────────────────────────────────────────────────────────────────────────╯
 Package Name        requests                            
 Version             2.34.2                              
 SHA-256 Digest      2a0d60c172f83ac6...1c061f4907e278e0 
 Scan Engine         STATIC_ONLY (112 Features)          
 Threat Probability  [██████████████████░░] 0.90 (90%)   
 Policy Zone         FAST_BLOCK                          

Threat Intelligence Findings:
  • Process execution attempt detected: 'platform.system'
  • Dynamic code evaluation detected: 're.compile'
  • CRITICAL: Obfuscated dynamic code execution pattern (eval + base64)

[🚫 FAST BLOCK ACTIVATED] Critical malware dropper detected via AST. 
Installation prohibited.
```

---

## 👥 Team
Built for the Hackathon by:
- **Member 1 (Jensy):** CLI Gateway, Static AST Engine, SQLite DB, ML Model Training.
- **Member 2 (Khushi):** Docker Sandbox Container, Dual-Phase Detonator, Dynamic Feature Extraction.
