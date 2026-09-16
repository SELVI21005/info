# ThreatLens AI – Malware Classification & Threat Detection System

ThreatLens AI is an AI-powered cybersecurity system that analyzes files using static analysis, YARA-based detection, and machine learning to classify potential malware and assess file risk.

## Features

- Static malware analysis
- MD5 and SHA-256 hashing
- File metadata and PE-header analysis
- String, URL/IP and API analysis
- YARA-based detection
- EMBER feature extraction
- Random Forest malware classification
- Malware / Benign prediction
- Risk scoring and alerts
- Detection logging
- Threat monitoring dashboard
- Malware analysis reports

## Tech Stack

- **Frontend:** React, Vite, JavaScript, CSS
- **Backend:** Python, FastAPI
- **Machine Learning:** Scikit-learn, Random Forest, EMBER, NumPy, Pandas
- **Security Analysis:** PEfile, LIEF, YARA

## ML Workflow

```text
PE File
   ↓
EMBER Feature Extraction
   ↓
2381 Features
   ↓
Random Forest
   ↓
Malware / Benign
   ↓
Risk Score & Alert
