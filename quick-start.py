#!/usr/bin/env python3
"""
Quick Start Script for Skill Gap Analyzer Demo
Starts both backend and frontend servers
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def print_banner():
    print("""
    ╔══════════════════════════════════════════════╗
    ║        🎯 Skill Gap Analyzer - Demo         ║
    ║      AI-Powered Career Development Tool      ║
    ╚══════════════════════════════════════════════╝
    """)

def check_prerequisites():
    """Check if required tools are available"""
    print("🔍 Checking prerequisites...")
    
    # Check Python
    try:
        result = subprocess.run(["python", "--version"], capture_output=True, text=True)
        print(f"✅ Python: {result.stdout.strip()}")
    except:
        print("❌ Python not found!")
        return False
    
    # Check Node.js
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        print(f"✅ Node.js: {result.stdout.strip()}")
    except:
        print("❌ Node.js not found!")
        return False
    
    # Check if virtual environment exists
    venv_path = Path("backend/venv")
    if venv_path.exists():
        print("✅ Backend virtual environment found")
    else:
        print("⚠️  Backend virtual environment not found")
        return False
    
    # Check if node_modules exists
    node_modules = Path("frontend/node_modules")
    if node_modules.exists():
        print("✅ Frontend dependencies installed")
    else:
        print("⚠️  Frontend dependencies not found")
        return False
    
    return True

def start_backend():
    """Start the FastAPI backend server"""
    print("🚀 Starting backend server...")
    
    # Change to backend directory and activate venv
    backend_dir = Path("backend")
    if sys.platform == "win32":
        cmd = [
            "cmd", "/c", 
            f"cd {backend_dir} && venv\\Scripts\\activate && python demo_main.py"
        ]
    else:
        cmd = [
            "bash", "-c",
            f"cd {backend_dir} && source venv/bin/activate && python demo_main.py"
        ]
    
    return subprocess.Popen(cmd, shell=True)

def start_frontend():
    """Start the React frontend server"""
    print("🌐 Starting frontend server...")
    
    # Change to frontend directory
    frontend_dir = Path("frontend")
    cmd = ["cmd", "/c", f"cd {frontend_dir} && npm start"] if sys.platform == "win32" else ["bash", "-c", f"cd {frontend_dir} && npm start"]
    
    return subprocess.Popen(cmd, shell=True)

def main():
    print_banner()
    
    if not check_prerequisites():
        print("\\n❌ Prerequisites check failed. Please run setup first:")
        print("   1. Backend: cd backend && python -m venv venv && venv\\Scripts\\activate && pip install -r requirements-demo.txt")
        print("   2. Frontend: cd frontend && npm install")
        return
    
    print("\\n🎉 All prerequisites met! Starting servers...")
    
    try:
        # Start backend
        backend_process = start_backend()
        time.sleep(3)  # Wait for backend to start
        
        # Start frontend  
        frontend_process = start_frontend()
        time.sleep(2)  # Wait for frontend to start
        
        print(f"""
        ╔══════════════════════════════════════════════╗
        ║                 🎉 SUCCESS!                  ║
        ║          Your app is now running!            ║
        ╚══════════════════════════════════════════════╝
        
        📱 Access your application:
        
        🌐 Frontend (React):     http://localhost:3000
        ⚡ Backend API:          http://localhost:8000
        📖 API Documentation:   http://localhost:8000/docs
        🩺 Health Check:        http://localhost:8000/health
        
        🎯 What you can do:
        1. Register a new user account
        2. Upload sample resumes (PDF/Word files)
        3. Analyze skill gaps for different jobs
        4. Browse course recommendations
        5. Explore the interactive dashboard
        
        💡 Tips:
        - Upload any PDF/Word resume to test skill extraction
        - Try different job titles for analysis
        - The demo uses simulated AI for skill analysis
        
        🛑 To stop: Press Ctrl+C in this terminal
        """)
        
        # Keep script running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\\n\\n🛑 Shutting down servers...")
            backend_process.terminate()
            frontend_process.terminate()
            print("✅ Servers stopped. Goodbye!")
            
    except Exception as e:
        print(f"❌ Error starting servers: {e}")
        return

if __name__ == "__main__":
    main()
