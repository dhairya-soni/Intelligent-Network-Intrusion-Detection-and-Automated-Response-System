@echo off
echo ========================================
echo Starting INIDARS Frontend
echo ========================================
echo.

cd frontend
echo Installing dependencies (first time only)...
if not exist "node_modules" (
    npm install
)
echo.
echo Starting Vite dev server...
npm run dev
