#!/usr/bin/env python3
"""
Development Startup Script for Skill Gap Analyzer
Starts both backend and frontend development servers
"""

import subprocess
import threading
import time
import os
import sys
import signal
from pathlib import Path

# Colors for terminal output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Print startup banner"""
    print(f"""
{Colors.BLUE}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                    SKILL GAP ANALYZER                       ║
║              Full-Stack Development Server                  ║
║                                                              ║
║  🚀 Starting Backend (FastAPI) + Frontend (React)          ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
    """)

def run_backend():
    """Run the FastAPI backend server"""
    backend_dir = Path(__file__).parent / "backend"
    
    print(f"{Colors.GREEN}📡 Starting Backend Server...{Colors.END}")
    print(f"{Colors.BLUE}   Location: {backend_dir}{Colors.END}")
    print(f"{Colors.BLUE}   URL: http://localhost:8000{Colors.END}")
    print(f"{Colors.BLUE}   API Docs: http://localhost:8000/docs{Colors.END}")
    
    try:
        # Change to backend directory
        os.chdir(backend_dir)
        
        # Start the backend server
        subprocess.run([
            sys.executable, "run.py"
        ], check=True)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}🛑 Backend server stopped{Colors.END}")
    except FileNotFoundError:
        print(f"{Colors.RED}❌ Backend run.py not found in {backend_dir}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Backend server error: {e}{Colors.END}")

def run_frontend():
    """Run the React frontend development server"""
    frontend_dir = Path(__file__).parent / "frontend"
    
    print(f"{Colors.GREEN}⚛️  Starting Frontend Server...{Colors.END}")
    print(f"{Colors.BLUE}   Location: {frontend_dir}{Colors.END}")
    print(f"{Colors.BLUE}   URL: http://localhost:3000{Colors.END}")
    
    try:
        # Change to frontend directory
        os.chdir(frontend_dir)
        
        # Check if node_modules exists
        if not (frontend_dir / "node_modules").exists():
            print(f"{Colors.YELLOW}📦 Installing npm dependencies...{Colors.END}")
            subprocess.run(["npm", "install"], check=True)
        
        # Start the frontend server
        subprocess.run([
            "npm", "start"
        ], check=True)
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}🛑 Frontend server stopped{Colors.END}")
    except FileNotFoundError:
        print(f"{Colors.RED}❌ Node.js/npm not found. Please install Node.js first.{Colors.END}")
        print(f"{Colors.BLUE}💡 Download from: https://nodejs.org/{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Frontend server error: {e}{Colors.END}")

def check_requirements():
    """Check if required tools are available"""
    print(f"{Colors.PURPLE}🔍 Checking requirements...{Colors.END}")
    
    # Check Python
    try:
        python_version = subprocess.run([sys.executable, "--version"], 
                                      capture_output=True, text=True)
        print(f"{Colors.GREEN}✅ {python_version.stdout.strip()}{Colors.END}")
    except Exception:
        print(f"{Colors.RED}❌ Python not found{Colors.END}")
        return False
    
    # Check Node.js
    try:
        node_version = subprocess.run(["node", "--version"], 
                                    capture_output=True, text=True, check=True)
        print(f"{Colors.GREEN}✅ Node.js {node_version.stdout.strip()}{Colors.END}")
    except Exception:
        print(f"{Colors.RED}❌ Node.js not found{Colors.END}")
        print(f"{Colors.BLUE}💡 Install from: https://nodejs.org/{Colors.END}")
        return False
    
    # Check npm
    try:
        npm_version = subprocess.run(["npm", "--version"], 
                                   capture_output=True, text=True, check=True)
        print(f"{Colors.GREEN}✅ npm {npm_version.stdout.strip()}{Colors.END}")
    except Exception:
        print(f"{Colors.RED}❌ npm not found{Colors.END}")
        return False
    
    # Check directories
    backend_dir = Path(__file__).parent / "backend"
    frontend_dir = Path(__file__).parent / "frontend"
    
    if not backend_dir.exists():
        print(f"{Colors.RED}❌ Backend directory not found: {backend_dir}{Colors.END}")
        return False
    print(f"{Colors.GREEN}✅ Backend directory found{Colors.END}")
    
    if not frontend_dir.exists():
        print(f"{Colors.RED}❌ Frontend directory not found: {frontend_dir}{Colors.END}")
        return False
    print(f"{Colors.GREEN}✅ Frontend directory found{Colors.END}")
    
    return True

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Colors.YELLOW}🛑 Shutting down servers...{Colors.END}")
    sys.exit(0)

def show_info():
    """Show helpful information"""
    print(f"""
{Colors.PURPLE}{Colors.BOLD}🌐 Application URLs:{Colors.END}
   Frontend:  http://localhost:3000
   Backend:   http://localhost:8000
   API Docs:  http://localhost:8000/docs
   Health:    http://localhost:8000/health

{Colors.PURPLE}{Colors.BOLD}📚 Key Features:{Colors.END}
   • Resume upload and skill extraction
   • AI-powered skill gap analysis
   • Interactive charts and visualizations
   • Course recommendations from multiple platforms
   • JWT authentication and user management

{Colors.PURPLE}{Colors.BOLD}⌨️  Controls:{Colors.END}
   • Ctrl+C to stop both servers
   • Servers will auto-reload on code changes
   • Frontend proxies API calls to backend

{Colors.PURPLE}{Colors.BOLD}📝 Development Notes:{Colors.END}
   • Backend uses FastAPI with auto-reload
   • Frontend uses React with hot-reload
   • Both servers start concurrently
   • Check terminal output for errors

{Colors.YELLOW}⚡ Ready for development!{Colors.END}
    """)

def main():
    """Main function to start both servers"""
    print_banner()
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check requirements
    if not check_requirements():
        print(f"\n{Colors.RED}❌ Requirements check failed. Please install missing dependencies.{Colors.END}")
        return
    
    print(f"\n{Colors.GREEN}✅ All requirements satisfied!{Colors.END}")
    
    # Show information
    show_info()
    
    # Start both servers in separate threads
    print(f"{Colors.BOLD}🚀 Starting development servers...{Colors.END}\n")
    
    backend_thread = threading.Thread(target=run_backend, daemon=True)
    frontend_thread = threading.Thread(target=run_frontend, daemon=True)
    
    # Start backend first
    backend_thread.start()
    time.sleep(2)  # Give backend time to start
    
    # Start frontend
    frontend_thread.start()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
            # Check if threads are still alive
            if not backend_thread.is_alive() and not frontend_thread.is_alive():
                print(f"\n{Colors.YELLOW}⚠️ Both servers have stopped{Colors.END}")
                break
                
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}🛑 Received interrupt signal{Colors.END}")
    
    print(f"{Colors.BLUE}👋 Thanks for using Skill Gap Analyzer!{Colors.END}")

if __name__ == "__main__":
    main()
