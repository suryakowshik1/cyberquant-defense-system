"""
CyberQuant AI - Main Application Runner
Starts FastAPI Web Server (Supports Localhost and Render Cloud Deployment)
"""
import uvicorn
import os
import sys

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("==================================================================")
    print("   CYBERQUANT AI: DEFENSIVE CYBER RISK & OPTIMIZATION PLATFORM    ")
    print("==================================================================")
    print(" [+] Initializing SQLite Database...")
    print(" [+] Loading FAIR Quantitative Risk Engine...")
    print(" [+] Initializing 0/1 Knapsack Security Budget Optimizer...")
    print(f" [+] Serving Executive SOC Dashboard on http://{host}:{port}")
    print("==================================================================")
    uvicorn.run("app.main:app", host=host, port=port, reload=False, server_header=False)

