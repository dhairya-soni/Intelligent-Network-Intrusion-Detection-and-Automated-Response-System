# INIDARS MVP - Intelligent Network Intrusion Detection System

## 40% Complete Working System

### What Works:
✅ Event ingestion pipeline
✅ Feature extraction from raw logs
✅ ML-based anomaly detection (Isolation Forest)
✅ Rule-based detection (5 attack patterns)
✅ Combined scoring system
✅ Alert generation and storage
✅ Dynamic React dashboard with real-time updates
✅ Statistics and metrics
✅ Working demo with realistic attacks

### Architecture:
```
Event → Parser → Feature Extractor → Detector (ML + Rules) → Alerts → Dashboard
```

### Tech Stack:
- Backend: Flask (Python) - Simple and reliable
- ML: scikit-learn (Isolation Forest)
- Frontend: React + Vite + Tailwind CSS
- Storage: In-memory (for simplicity, easily upgradeable to DB)

### Quick Start:

#### Terminal 1 - Backend:
```bash
cd inidars-mvp/backend
pip install -r requirements.txt
python app.py
```

#### Terminal 2 - Frontend:
```bash
cd inidars-mvp/frontend
npm install
npm run dev
```

#### Terminal 3 - Demo:
```bash
cd inidars-mvp
python demo.py brute_force
```

### Project Structure:
```
inidars-mvp/
├── backend/
│   ├── app.py                 # Flask API
│   ├── detector.py            # ML + Rule detection
│   ├── feature_extractor.py   # Feature extraction
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Main app
│   │   ├── Dashboard.jsx     # Statistics
│   │   ├── Alerts.jsx        # Alert list
│   │   └── api.js           # API client
│   ├── package.json
│   └── vite.config.js
├── demo.py                   # Attack simulator
└── README.md
```

### Features:

**Detection:**
- ML Anomaly Scoring (0-1 scale)
- 5 Rule-based patterns:
  - Brute Force (multiple failed logins)
  - Port Scan (rapid port access)
  - SQL Injection (malicious SQL patterns)
  - DDoS (high request volume)
  - Malware (suspicious file patterns)

**Dashboard:**
- Real-time alert feed
- Statistics cards (total, critical, high, medium, low)
- Severity distribution chart
- Auto-refresh every 3 seconds
- Filter by severity
- Alert details view

**Demo:**
- Generates realistic attack events
- Multiple attack types
- Instant feedback in dashboard

### API Endpoints:
- POST /api/events - Ingest security event
- GET /api/alerts - Get all alerts
- GET /api/alerts/<id> - Get specific alert
- GET /api/stats - Get statistics
- DELETE /api/alerts - Clear all alerts

### Next Steps (to reach 100%):
- [ ] Persistent database (SQLite/PostgreSQL)
- [ ] User authentication
- [ ] Response automation (IP blocking)
- [ ] Email/Slack notifications
- [ ] Historical analysis
- [ ] Custom rule editor
- [ ] Advanced ML models
- [ ] Real log file ingestion
