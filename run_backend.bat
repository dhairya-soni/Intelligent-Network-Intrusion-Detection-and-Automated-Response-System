@echo off
echo ========================================
echo Starting INIDARS Backend
echo ========================================
echo.

cd backend
echo Installing dependencies...
pip install -r requirements.txt --quiet
echo.
echo Starting Flask server...
python app.py
