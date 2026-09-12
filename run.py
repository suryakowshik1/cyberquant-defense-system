"""
CyberQuant AI - Main Application Runner
Starts FastAPI Web Server on http://127.0.0.1:8000
"""
import uvicorn
import os
import sys

if __name__ == "__main__":
    print("==================================================================")
    print("   CYBERQUANT AI: DEFENSIVE CYBER RISK & OPTIMIZATION PLATFORM    ")
    print("==================================================================")
    print(" [+] Initializing SQLite Database...")
    print(" [+] Loading FAIR Quantitative Risk Engine...")
    print(" [+] Initializing 0/1 Knapsack Security Budget Optimizer...")
    print(" [+] Serving Executive SOC Dashboard at: http://127.0.0.1:8000")
    print("==================================================================")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
