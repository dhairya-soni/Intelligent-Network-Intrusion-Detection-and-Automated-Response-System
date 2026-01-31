# INIDARS MVP - Quick Start Guide

## 🚀 Getting Started (5 Minutes)

### Prerequisites
- Python 3.8+ installed
- Node.js 16+ installed
- Internet connection (for installing dependencies)

### Step 1: Install Backend Dependencies

Open Command Prompt:
```cmd
cd inidars-mvp\backend
pip install -r requirements.txt
```

### Step 2: Install Frontend Dependencies

Open a NEW Command Prompt:
```cmd
cd inidars-mvp\frontend
npm install
```

### Step 3: Start the System

**Terminal 1 - Backend:**
```cmd
cd inidars-mvp
run_backend.bat
```
Wait for: `Running on http://0.0.0.0:5000`

**Terminal 2 - Frontend:**
```cmd
cd inidars-mvp
run_frontend.bat
```
Wait for: `Local: http://localhost:3000/`

**Terminal 3 - Demo:**
```cmd
cd inidars-mvp
run_demo.bat brute_force
```

### Step 4: View Dashboard

Open browser to: **http://localhost:3000**

You should see:
- ✅ Dark professional dashboard
- ✅ Statistics cards showing alerts
- ✅ Recent activity feed
- ✅ Threat type distribution

---

## 📊 What You'll See

### Dashboard View
- **Total Alerts**: Count of all detected threats
- **Severity Breakdown**: Critical, High, Medium, Low
- **Threat Types**: Distribution of attack patterns
- **Recent Activity**: Latest 10 alerts
- **Detection Pipeline**: System status

### Alerts View
- **Alert Table**: All alerts with details
- **Filters**: Filter by severity
- **Alert Details**: Click any alert for full information

---

## 🎯 Demo Scenarios

Run different attack simulations:

```cmd
# Brute force attack (10 failed logins)
run_demo.bat brute_force

# Port scan (15 ports scanned)
run_demo.bat port_scan

# SQL injection attempts
run_demo.bat sql_injection

# DDoS attack (60 requests)
run_demo.bat ddos

# Malware activity
run_demo.bat malware

# Normal traffic (baseline)
run_demo.bat normal
```

---

## 🔍 How It Works

### Detection Pipeline

```
1. Event Ingestion
   ↓
2. Feature Extraction (10 features)
   ↓
3. ML Detection (Isolation Forest)
   ↓
4. Rule-Based Detection (5 rules)
   ↓
5. Alert Generation
   ↓
6. Dashboard Display
```

### ML Detection
- **Model**: Isolation Forest
- **Features**: 10 numerical features extracted from each event
- **Score**: 0-1 (higher = more anomalous)
- **Threshold**: Events with score > 0.6 flagged

### Rule-Based Detection
1. **Brute Force**: 3+ failed logins from same IP
2. **Port Scan**: 10+ different ports accessed
3. **SQL Injection**: Malicious SQL patterns in payload
4. **DDoS**: 50+ requests from same source
5. **Malware**: Suspicious file/process patterns

### Combined Detection
- **CRITICAL**: High ML score (>0.85) + Rule match
- **HIGH**: High ML score (>0.75) OR Rule match
- **MEDIUM**: Moderate ML score (>0.6)
- **LOW**: Low ML score but flagged

---

## 📝 Testing Checklist

### ✅ Backend Working
- [ ] Terminal shows "Running on http://0.0.0.0:5000"
- [ ] No errors in terminal
- [ ] http://localhost:5000/health returns JSON

### ✅ Frontend Working
- [ ] Terminal shows "Local: http://localhost:3000/"
- [ ] No errors in terminal
- [ ] Dashboard loads with dark theme
- [ ] Navigation works (Dashboard ↔ Alerts)

### ✅ Demo Working
- [ ] Demo completes successfully
- [ ] Alerts appear in dashboard
- [ ] Statistics update
- [ ] Can view alert details

### ✅ Detection Working
- [ ] Brute force detected (should create CRITICAL alerts)
- [ ] Port scan detected (should create HIGH alerts)
- [ ] SQL injection detected (should create alerts)
- [ ] Normal traffic doesn't create many alerts

---

## 🎓 For Your Presentation

### Key Points to Highlight

**1. Complete Detection Pipeline** (40% target achieved)
- ✅ Event ingestion and parsing
- ✅ Feature extraction (10 features)
- ✅ ML-based detection (Isolation Forest)
- ✅ Rule-based detection (5 rules)
- ✅ Alert generation and storage
- ✅ Dynamic dashboard with statistics

**2. Real Detection Capability**
- ML model trained on normal behavior
- Detects anomalies with confidence scores
- Rule engine catches known attack patterns
- Combined approach for accuracy

**3. Professional UI**
- Real-time updates (3-second refresh)
- Statistics and metrics
- Alert filtering and details
- Clean, modern design

**4. Working Demo**
- Multiple attack scenarios
- Realistic event generation
- Instant feedback
- Easy to demonstrate

### Demo Flow for Guide

1. **Show clean dashboard** (no alerts)
2. **Run brute force demo**
3. **Show alerts appearing in real-time**
4. **Click alert to show detection details**
5. **Show ML score and rule match**
6. **Explain recommendation**
7. **Show statistics update**

---

## 🔧 Troubleshooting

### Backend won't start
```cmd
# Check Python version
python --version

# Reinstall dependencies
pip install -r backend/requirements.txt --force-reinstall
```

### Frontend won't start
```cmd
# Delete and reinstall
cd frontend
rmdir /s /q node_modules
del package-lock.json
npm install
```

### No alerts appearing
1. Check backend is running (Terminal 1)
2. Check frontend is running (Terminal 2)
3. Hard refresh browser (Ctrl + Shift + R)
4. Check browser console (F12) for errors

### Port already in use
```cmd
# Kill process on port 5000 (backend)
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Kill process on port 3000 (frontend)
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

---

## 📈 Next Steps (to reach 100%)

Current: **40% Complete** ✅

Remaining 60%:
- [ ] Persistent database (SQLite/PostgreSQL)
- [ ] User authentication and authorization
- [ ] Automated response actions (IP blocking)
- [ ] Email/Slack notifications
- [ ] Historical analysis and reporting
- [ ] Custom rule editor
- [ ] Advanced ML models (deep learning)
- [ ] Real log file ingestion (Syslog, etc.)
- [ ] Multi-node deployment
- [ ] Performance optimization

---

## 🎉 Success Indicators

You've successfully set up INIDARS MVP when:

✅ Backend terminal shows "Running on http://0.0.0.0:5000"
✅ Frontend terminal shows "Local: http://localhost:3000/"
✅ Dashboard loads with dark theme
✅ Demo creates alerts
✅ Alerts show in dashboard with ML scores
✅ Statistics update correctly
✅ Can filter and view alert details

**You now have a working 40% complete intrusion detection system!** 🎉

---

Made with ❤️ for your capstone project
