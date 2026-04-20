#  INIDARS - Intelligent Network Intrusion Detection & Automated Response System

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18.0%2B-61DAFB?logo=react)](https://reactjs.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?logo=flask)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5%2B-orange?logo=scikit-learn)](https://scikit-learn.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0%2B-blue)](https://xgboost.readthedocs.io/)
[![LightGBM](https://img.shields.io/badge/LightGBM-4.0%2B-green)](https://lightgbm.readthedocs.io/)

> **An intelligent, real-time Network Intrusion Detection System (NIDS) powered by an ensemble of three ML models, rule-based detection, explainable AI, external threat intelligence, and automated response — with a full monitoring dashboard.**

<div align="center">
  <img src="https://img.shields.io/badge/ML%20Model-Ensemble%20(RF%2BXGB%2BLGB)-red?style=for-the-badge" alt="ML Model">
  <img src="https://img.shields.io/badge/Accuracy-99.94%25%20(Holdout)-success?style=for-the-badge" alt="Accuracy">
  <img src="https://img.shields.io/badge/Status-85%25%20Complete-brightgreen?style=for-the-badge" alt="Status">
</div>

---

## Demo Overview

INIDARS combines a **soft-voting ensemble of three ML models** with an **expert rule engine** to detect network threats in real-time. The system processes network events, classifies traffic into 5 categories (Normal, DoS, Probe, R2L, U2R), explains *why* it flagged each alert, and cross-checks IPs against AbuseIPDB threat intelligence.

### Key Capabilities
- **Ensemble ML Detection**: Random Forest + XGBoost + LightGBM (soft voting) — 99.94% accuracy on same-distribution holdout
- **Multi-Class Classification**: Identifies attack category (DoS, Probe, R2L, U2R) not just "malicious"
- **Explainable AI**: Per-alert feature anomaly scores explaining *why* the model flagged each event
- **Rule-Based Engine**: 5 attack pattern detectors (Brute Force, Port Scan, SQL Injection, DDoS, Malware)
- **External Threat Intel**: AbuseIPDB integration with 1-hour caching for live IP reputation lookup
- **SQLite Persistence**: All alerts, blocked IPs, and action logs survive restarts
- **Real-Time Dashboard**: React-based monitoring with severity analytics and model benchmarks
- **Export System**: CSV and PDF report export with full alert data
- **Email Alerts**: Automatic SMTP notifications on CRITICAL severity detections

---

## Features

### Detection Engine
- **Ensemble Architecture**: RF + XGBoost + LightGBM averaged via soft voting for superior accuracy
- **Multi-Class Output**: Classifies into Normal / DoS / Probe / R2L / U2R (not just binary)
- **Rule Engine**: 5 pattern detectors layered on top of ML predictions
- **Confidence Scoring**: Per-class probability output (0–1) with ensemble averaging
- **Severity Triage**: CRITICAL / HIGH / MEDIUM / LOW with automated assignment

### Explainability & Threat Intel
- **Feature Anomaly Scores**: Z-score deviation from normal traffic baseline for each of 10 features
- **Top-5 Anomalous Features**: Each alert shows which network features triggered the detection
- **AbuseIPDB Integration**: Live abuse score, total reports, country, ISP, risk level per IP
- **Attack Category Badges**: DoS / Probe / R2L / U2R labels on every alert card

### Response & Investigation
- **IP Blocking**: One-click blocking with SQLite-persisted storage
- **IP Investigation**: Complete timeline view of suspicious IPs
- **Action Logging**: Full audit trail of all security responses in database
- **Alert Management**: Per-alert deletion and bulk clearing

### Monitoring & Analytics
- **Real-Time Dashboard**: Live event streaming with auto-refresh
- **Benchmarks Page**: Compare our model to published research papers with methodology explanation
- **Threat Visualization**: Severity distribution, attack type breakdown
- **Top Offenders**: Ranking of most active malicious IPs
- **Model Performance**: Live accuracy, precision, recall, F1 per class
- **Export**: CSV download and branded PDF report

---

## Architecture

```
┌─────────────────┐
│   USER BROWSER  │  (Opens http://localhost:3000)
└────────┬────────┘
         │
         v
┌─────────────────────────────────────────┐
│        REACT FRONTEND (Port 3000)       │
│  - Dashboard.jsx    (stats + overview)  │
│  - AlertsList.jsx   (alerts + explain)  │
│  - Benchmarks.jsx   (model comparison)  │
│  - BlockedIPs.jsx                       │
│  - IPHistoryModal.jsx                   │
└────────┬────────────────────────────────┘
         │ HTTP Requests (via api.js)
         v
┌─────────────────────────────────────────┐
│       FLASK BACKEND (Port 5000)         │
│                                         │
│  app.py ──→ Routes HTTP requests        │
│     │                                   │
│     ├──→ detector.py                    │
│     │       ├── models.py (Ensemble)    │
│     │       └── feature_extractor.py   │
│     │                                   │
│     ├──→ database.py (SQLite WAL)       │
│     ├──→ threat_intel.py (AbuseIPDB)    │
│     └──→ notifier.py (Email SMTP)       │
└─────────────────────────────────────────┘
         ^
         │ Simulates attack traffic
┌────────┴────────┐
│    demo.py      │
└─────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Flask 3.0, Python 3.8+ |
| **ML/AI** | scikit-learn (Random Forest), XGBoost, LightGBM, Soft Voting Ensemble |
| **Frontend** | React 18, Vite, Tailwind CSS |
| **Database** | SQLite (WAL mode, persistent) |
| **Data** | Pandas, NumPy, Pickle (model serialization) |
| **Export** | fpdf2 (PDF), csv (CSV) |
| **Threat Intel** | AbuseIPDB REST API |
| **Notifications** | smtplib (SMTP email) |
| **Dataset** | NSL-KDD (125,973 training + 22,544 KDDTest+ samples) |

---

## Model Performance

Trained and evaluated on the **NSL-KDD** dataset. Two evaluation modes are reported — see the in-app Benchmarks page for full comparison against published papers.

### Same-Distribution Holdout (20% split of KDDTrain+)
*This is the standard method used in most published research papers*

| Metric | Score |
|--------|-------|
| **Accuracy** | 99.94% |
| **Precision** | 99.92% |
| **Recall** | 99.94% |
| **F1-Score** | 99.93% |

### Official KDDTest+ (Novel Attack Generalization)
*Harder evaluation — KDDTest+ contains attack subtypes not present in training data*

| Metric | Score |
|--------|-------|
| **Accuracy** | 79.33% |
| **Precision** | ~82% |
| **Recall** | ~79% |
| **F1-Score** | ~78% |

**Why two numbers?** Most papers report on a holdout split from the same distribution (99%+ accuracy), which is reproducible but optimistic. KDDTest+ is harder because it includes novel attack variants. Both numbers are shown on the Benchmarks page with full methodology explanation.

### Dataset Details
- **Training Samples**: 125,973 network connections (KDDTrain+)
- **Test Samples**: 22,544 (KDDTest+ official split)
- **Features**: 41 network attributes (protocol, bytes, flags, connection stats, etc.)
- **Classes**: Normal (67,343) vs. DoS / Probe / R2L / U2R attacks
- **Class Imbalance**: Handled via `class_weight='balanced'` across all three models

---

## Installation

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

# Create virtual environment
python -m venv venv

# Activate (Windows):
venv\Scripts\activate
# Activate (macOS/Linux):
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Download NSL-KDD Dataset
Download from [Kaggle NSL-KDD](https://www.kaggle.com/datasets/hassan06/nslkdd) and place these two files inside the `backend/` folder:
- `KDDTrain+.txt`
- `KDDTest+.txt`

### 4. Train the ML Model
```bash
# Inside backend/ with venv activated
python train_model.py
```
This trains the RF + XGBoost + LightGBM ensemble and saves `trained_model.pkl`. Takes 2–5 minutes. You will see accuracy metrics printed when done.

### 5. Start the Backend
```bash
python app.py
```
Server runs at `http://localhost:5000`

### 6. Frontend Setup (new terminal)
```bash
cd frontend

# Install dependencies
npm install

# Start Development Server
npm run dev
```
Access at `http://localhost:3000`

---

## Usage

### Quick Start (Windows Batch Scripts)
```bash
# Terminal 1: Start Backend
run_backend.bat

# Terminal 2: Start Frontend
run_frontend.bat

# Terminal 3: Run Demo
run_demo.bat mixed_traffic
```

### Generate Demo Traffic
```bash
cd backend
# Activate venv first, then:

python demo.py mixed_traffic     # 60% normal, 30% suspicious, 10% attacks
python demo.py brute_force
python demo.py port_scan
python demo.py sql_injection
python demo.py ddos
python demo.py malware
```

### Dashboard Features
- **Dashboard tab**: Real-time stats, severity distribution, top threat sources, model metrics
- **Alerts tab**: All alerts with attack category badges; click any row to expand feature anomaly scores
- **Benchmarks tab**: Compare our model vs. published research papers; toggle holdout vs. KDDTest+ mode
- **Blocked IPs tab**: Manage blocked IP addresses with unblock functionality

### Optional: Enable AbuseIPDB Threat Intelligence
1. Create a free account at [abuseipdb.com](https://www.abuseipdb.com)
2. Get your API key from the dashboard
3. Set the environment variable before starting the backend:
   ```bash
   # Windows:
   set ABUSEIPDB_KEY=your_key_here
   python app.py

   # macOS/Linux:
   export ABUSEIPDB_KEY=your_key_here
   python app.py
   ```
4. In the Alerts tab, each alert will show an **"Check AbuseIPDB"** button

### Optional: Enable Email Notifications (CRITICAL alerts)
Set these environment variables before starting the backend:
```bash
# Windows:
set SMTP_HOST=smtp.gmail.com
set SMTP_PORT=587
set SMTP_USER=your@gmail.com
set SMTP_PASS=your_app_password
set NOTIFY_EMAIL=alert-recipient@email.com
python app.py
```
For Gmail, use an [App Password](https://myaccount.google.com/apppasswords), not your regular password.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events` | POST | Ingest a security event |
| `/api/alerts` | GET | Get all alerts (filter: `?severity=HIGH`) |
| `/api/alerts/<id>` | DELETE | Delete a specific alert |
| `/api/alerts/clear` | POST | Clear all alerts |
| `/api/block-ip` | POST | Block an IP address |
| `/api/blocked-ips` | GET | List all blocked IPs |
| `/api/unblock-ip` | POST | Unblock an IP address |
| `/api/ip-history/<ip>` | GET | Get full IP investigation report |
| `/api/stats` | GET | System statistics |
| `/api/model/info` | GET | ML model performance metrics |
| `/api/benchmarks` | GET | Model benchmarks vs. research papers |
| `/api/threat-intel/<ip>` | GET | AbuseIPDB lookup for an IP |
| `/api/threat-intel/status` | GET | Check if AbuseIPDB key is configured |
| `/api/export/csv` | GET | Download alerts as CSV |
| `/api/export/pdf` | GET | Download full PDF security report |

---

## Roadmap

### Completed (85%)
- [x] Event ingestion pipeline
- [x] Feature extraction (10 real-time + 41 NSL-KDD features)
- [x] Ensemble ML detection (RF + XGBoost + LightGBM soft voting)
- [x] Multi-class classification (Normal / DoS / Probe / R2L / U2R)
- [x] Rule-based detection (5 patterns)
- [x] Combined scoring system
- [x] React dashboard with real-time updates
- [x] IP blocking/unblocking with SQLite persistence
- [x] IP investigation with full timeline
- [x] Mixed traffic simulation
- [x] NSL-KDD model training with class balancing
- [x] Explainable AI (per-alert feature anomaly scores)
- [x] AbuseIPDB threat intelligence integration
- [x] SQLite database (alerts, blocked IPs, action logs persist across restarts)
- [x] CSV and PDF export
- [x] Email notifications for CRITICAL alerts
- [x] Benchmarks page comparing to published research papers

### Planned (To reach 100%)
- [ ] PostgreSQL migration for production scale
- [ ] User authentication & multi-tenancy
- [ ] REST API authentication (JWT)
- [ ] Docker containerization
- [ ] Real log file ingestion (syslog, pcap)
- [ ] Custom rule editor UI
- [ ] Historical trend charts (24h/7d/30d)
- [ ] Advanced attack maps and timeline visualizations

---

Project Link: [https://github.com/dhairya-soni/Intelligent-Network-Intrusion-Detection-and-Automated-Response-System](https://github.com/dhairya-soni/Intelligent-Network-Intrusion-Detection-and-Automated-Response-System)
