# 🛡️ INIDARS - Intelligent Network Intrusion Detection & Automated Response System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18.0%2B-61DAFB?logo=react)](https://reactjs.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?logo=flask)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange?logo=scikit-learn)](https://scikit-learn.org/)

> **An intelligent, real-time Network Intrusion Detection System (NIDS) powered by Machine Learning and rule-based detection, featuring automated threat response and interactive investigation capabilities.**

<div align="center">
  <img src="https://img.shields.io/badge/ML%20Model-NSL--KDD%20Trained-red?style=for-the-badge" alt="ML Model">
  <img src="https://img.shields.io/badge/Accuracy-76.74%25-success?style=for-the-badge" alt="Accuracy">
  <img src="https://img.shields.io/badge/Status-40%25%20Complete-yellow?style=for-the-badge" alt="Status">
</div>

---

## 🎥 Demo Overview

INIDARS (Intelligent Network Intrusion Detection and Automated Response System) combines **supervised machine learning** with **expert rules** to detect network threats in real-time. The system processes network events, extracts features, and classifies traffic as normal or malicious with automated response capabilities.

### Key Capabilities
- 🧠 **ML-Powered Detection**: Isolation Forest + Random Forest trained on 125,973 NSL-KDD samples
- 🔍 **Rule-Based Engine**: 5 attack pattern detectors (Brute Force, Port Scan, SQL Injection, DDoS, Malware)
- ⚡ **Real-Time Processing**: <100ms detection latency
- 🚫 **Automated Response**: IP blocking with investigation tools
- 📊 **Live Dashboard**: React-based monitoring with severity analytics

---

## ✨ Features

### 🔐 Detection Engine
- **Hybrid Architecture**: Combines ML anomaly detection with signature-based rules
- **ML Model**: Trained on NSL-KDD dataset with 41 network features
- **Attack Patterns**: Brute Force, Port Scan, SQL Injection, DDoS, Malware detection
- **Confidence Scoring**: ML anomaly scores (0-1) with rule-based validation
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW with automated triage

### 🛡️ Response & Investigation
- **IP Blocking**: One-click blocking with persistent storage
- **IP Investigation**: Complete timeline view of suspicious IPs
- **Action Logging**: Audit trail of all security responses
- **Alert Management**: Individual alert deletion and bulk clearing

### 📈 Monitoring & Analytics
- **Real-Time Dashboard**: Live event streaming with auto-refresh
- **Threat Visualization**: Severity distribution, attack type breakdown
- **Top Offenders**: Ranking of most active malicious IPs
- **Model Performance**: Live accuracy, precision, recall metrics
- **Traffic Statistics**: Total events vs. threats detected

---

## 🏗️ Architecture

```
Network Traffic → [Flask Backend] → Feature Extraction → [ML Detector + Rules] → Alert Generation
                                      ↓                        ↓
                                  [Isolation Forest]    [5 Detection Rules]
                                      ↓                        ↓
                              Anomaly Score (0-1)      Pattern Matching
                                      ↓                        ↓
                              Combined Scoring ←──────────────┘
                                      ↓
                            Severity Assessment → [IP Blocking/Investigation]
                                      ↓
                         [React Dashboard] ← WebSocket/HTTP API
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Flask 3.0, Python 3.8+ |
| **ML/AI** | scikit-learn (Isolation Forest, Random Forest) |
| **Frontend** | React 18, Vite, Tailwind CSS |
| **Data** | Pandas, NumPy, Pickle (model serialization) |
| **Dataset** | NSL-KDD (125,973 training samples) |

---

## 🧠 Model Performance

Trained and evaluated on the **NSL-KDD** dataset, the standard benchmark for intrusion detection systems.

| Metric | Score | Status |
|--------|-------|--------|
| **Accuracy** | 76.74% | ✅ |
| **Precision** | 96.71% | ✅ Excellent |
| **Recall** | 61.22% | ✅ Good |
| **F1-Score** | 74.98% | ✅ Balanced |

**Dataset Details:**
- **Training Samples**: 125,973 network connections
- **Features**: 41 network attributes (protocol, bytes, flags, etc.)
- **Classes**: Normal (67,343) vs. Attack (58,630)
- **Attack Types**: DoS, Probe, R2L, U2R

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- pip & npm

### 1. Clone Repository
```bash
git clone https://github.com/dhairya-soni/Intelligent-Network-Intrusion-Detection-and-Automated-Response-System.git
cd inidars-mvp
```

### 2. Backend Setup
```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download NSL-KDD Dataset
# Place KDDTrain+.txt and KDDTest+.txt in backend/ folder
# Download from: https://www.kaggle.com/datasets/hassan06/nslkdd

# Train the ML Model (First time only)
python train_model.py

# Start Backend Server
python app.py
```
Server runs at `http://localhost:5000`

### 3. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start Development Server
npm run dev
```
Access at `http://localhost:3000`

---

## 🎮 Usage

### Quick Start (Automated)
Use the provided batch scripts (Windows):
```bash
# Terminal 1: Start Backend
run_backend.bat

# Terminal 2: Start Frontend  
run_frontend.bat

# Terminal 3: Run Demo
run_demo.bat mixed_traffic
```

### Manual Demo Execution

**1. Generate Traffic**
```bash
# Mixed traffic (60% normal, 30% suspicious, 10% attacks)
python demo.py mixed_traffic

# Specific attack types
python demo.py brute_force
python demo.py port_scan
python demo.py sql_injection
python demo.py ddos
python demo.py malware
```

**2. Interact with Dashboard**
- View real-time alerts in the Dashboard
- Click 🔍 **Investigate** on any alert to see IP history
- Click 🚫 **Block** to block malicious IPs
- Monitor model performance metrics
- Switch to "Blocked" tab to manage blocked IPs

**3. API Endpoints**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events` | POST | Ingest security event |
| `/api/alerts` | GET | Get all alerts (filter by severity) |
| `/api/alerts/<id>` | DELETE | Delete specific alert |
| `/api/block-ip` | POST | Block an IP address |
| `/api/blocked-ips` | GET | List blocked IPs |
| `/api/ip-history/<ip>` | GET | Get IP investigation report |
| `/api/stats` | GET | System statistics |
| `/api/model/info` | GET | ML model performance metrics |

---

## 📊 Screenshots(WILL ADD SOON!)

### Dashboard Overview
*Real-time monitoring with model performance metrics*
```[Dashboard showing Total Events, Threats Detected, Blocked IPs, and Model Accuracy 76.74%]```

### IP Investigation
*Deep dive into suspicious IP activity*
```[IP History Modal showing timeline, alerts, and actions]```

### Alert Management
*Working action buttons (Investigate, Block, Delete)*
```[Alerts table with severity badges and action buttons]```

### Blocked IPs
*Management interface for blocked addresses*
```[Blocked IPs table with unblock functionality]```

---

## 🗺️ Roadmap

### ✅ Completed (40%)
- [x] Event ingestion pipeline
- [x] Feature extraction (10 basic + 41 NSL-KDD features)
- [x] ML anomaly detection (Isolation Forest)
- [x] Rule-based detection (5 patterns)
- [x] Combined scoring system
- [x] Alert generation and storage
- [x] React dashboard with real-time updates
- [x] IP blocking/unblocking
- [x] IP investigation with timeline
- [x] Mixed traffic simulation
- [x] NSL-KDD model training

### 🔄 In Progress
- [ ] Historical analysis (24h/7d/30d trends)
- [ ] Advanced visualizations (attack maps, timelines)
- [ ] Export reports (PDF/CSV)

### ⏳ Planned (To reach 100%)
- [ ] PostgreSQL database integration
- [ ] User authentication & multi-tenancy
- [ ] Email/Slack notifications
- [ ] REST API authentication (JWT)
- [ ] Docker containerization
- [ ] Real log file ingestion (syslog, pcap)
- [ ] Custom rule editor UI
- [ ] Threat intelligence feeds (VirusTotal, AbuseIPDB)

---

Project Link: [https://github.com/dhairya-soni/Intelligent-Network-Intrusion-Detection-and-Automated-Response-System](https://github.com/dhairya-soni/Intelligent-Network-Intrusion-Detection-and-Automated-Response-System)

---


