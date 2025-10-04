#!/usr/bin/env python3
"""
Development Helper Script for Skill Gap Analyzer Backend
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def run_server():
    """Start the development server"""
    print("🚀 Starting development server...")
    try:
        subprocess.run([sys.executable, "run.py"], cwd=Path(__file__).parent)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")

def test_setup():
    """Run setup tests"""
    print("🧪 Running setup tests...")
    try:
        subprocess.run([sys.executable, "test_setup.py"], cwd=Path(__file__).parent)
    except Exception as e:
        print(f"❌ Setup test failed: {e}")

def install_deps():
    """Install dependencies"""
    print("📦 Installing dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
    except Exception as e:
        print(f"❌ Failed to install dependencies: {e}")

def download_models():
    """Download required ML models"""
    print("🧠 Downloading ML models...")
    try:
        # Download spaCy model
        subprocess.run([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
        print("✅ spaCy model downloaded successfully")
    except Exception as e:
        print(f"❌ Failed to download models: {e}")

def preprocess_data():
    """Run data preprocessing"""
    print("🔄 Running data preprocessing...")
    try:
        preprocess_script = project_root / "scripts" / "preprocess_data.py"
        if preprocess_script.exists():
            subprocess.run([sys.executable, str(preprocess_script)])
            print("✅ Data preprocessing completed")
        else:
            print("⚠️ Preprocessing script not found")
    except Exception as e:
        print(f"❌ Data preprocessing failed: {e}")

def create_env():
    """Create .env file from template"""
    print("⚙️ Setting up environment configuration...")
    
    env_example = project_root / ".env.example"
    env_file = project_root / ".env"
    
    if env_file.exists():
        print("⚠️ .env file already exists")
        return
    
    if env_example.exists():
        try:
            with open(env_example, 'r') as src, open(env_file, 'w') as dst:
                dst.write(src.read())
            print("✅ .env file created from template")
            print("💡 Please edit .env file with your configurations")
        except Exception as e:
            print(f"❌ Failed to create .env file: {e}")
    else:
        print("❌ .env.example template not found")

def run_tests():
    """Run test suite (if available)"""
    print("🧪 Running test suite...")
    
    test_dir = Path(__file__).parent / "tests"
    if test_dir.exists():
        try:
            subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"])
        except Exception as e:
            print(f"❌ Tests failed: {e}")
    else:
        print("⚠️ Test directory not found")

def lint_code():
    """Run code linting (if tools available)"""
    print("🔍 Running code linting...")
    
    try:
        # Try running flake8
        subprocess.run([sys.executable, "-m", "flake8", "app/"], check=False)
    except FileNotFoundError:
        print("⚠️ flake8 not installed, skipping linting")

def format_code():
    """Format code with black (if available)"""
    print("🎨 Formatting code...")
    
    try:
        subprocess.run([sys.executable, "-m", "black", "app/"], check=False)
        print("✅ Code formatting completed")
    except FileNotFoundError:
        print("⚠️ black not installed, skipping formatting")

def clean():
    """Clean up generated files"""
    print("🧹 Cleaning up...")
    
    patterns_to_remove = [
        "**/__pycache__",
        "**/*.pyc",
        "**/*.pyo",
        "**/*.pyd",
        "**/.pytest_cache",
        "app.log",
        "*.egg-info"
    ]
    
    import shutil
    import glob
    
    for pattern in patterns_to_remove:
        for path in Path(__file__).parent.glob(pattern):
            if path.is_file():
                path.unlink()
                print(f"  Removed file: {path}")
            elif path.is_dir():
                shutil.rmtree(path)
                print(f"  Removed directory: {path}")
    
    print("✅ Cleanup completed")

def show_info():
    """Show development information"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              SKILL GAP ANALYZER - DEV INFO                  ║
    ╚══════════════════════════════════════════════════════════════╝
    
    📁 Project Structure:
       backend/                 # Backend API (FastAPI)
       ├── app/                 # Application code
       │   ├── api/             # API endpoints
       │   ├── models/          # Data models
       │   ├── services/        # Business logic
       │   └── utils/           # Utilities
       ├── uploads/             # File uploads
       ├── tests/              # Test suite
       └── requirements.txt    # Dependencies
    
    🚀 Quick Commands:
       python dev.py server    # Start development server
       python dev.py test      # Run setup tests
       python dev.py setup     # Full setup (deps + models + env)
    
    🌐 Development URLs:
       API Server:     http://localhost:8000
       Documentation:  http://localhost:8000/docs
       Health Check:   http://localhost:8000/health
    
    📚 Key Features:
       • Resume upload and processing
       • AI-powered skill extraction
       • Skill gap analysis
       • Course recommendations
       • Interactive visualizations
       • JWT authentication
    """)

def full_setup():
    """Run complete setup process"""
    print("🛠️ Running complete setup...")
    
    steps = [
        ("Installing dependencies", install_deps),
        ("Downloading ML models", download_models),
        ("Creating environment config", create_env),
        ("Testing setup", test_setup),
    ]
    
    for step_name, step_func in steps:
        print(f"\n{'='*50}")
        print(f"Step: {step_name}")
        print(f"{'='*50}")
        step_func()
    
    print(f"\n{'='*50}")
    print("SETUP COMPLETE")
    print(f"{'='*50}")
    print("🎉 Your development environment is ready!")
    print("💡 Next steps:")
    print("   1. Configure your .env file with database settings")
    print("   2. Set up your MySQL database")
    print("   3. Run 'python dev.py server' to start the API")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Development helper for Skill Gap Analyzer Backend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dev.py server       # Start development server
  python dev.py test         # Run setup tests
  python dev.py setup        # Complete setup process
  python dev.py info         # Show project information
        """
    )
    
    parser.add_argument(
        "command",
        choices=[
            "server", "test", "install", "models", "preprocess", 
            "env", "tests", "lint", "format", "clean", "info", "setup"
        ],
        help="Command to run"
    )
    
    args = parser.parse_args()
    
    commands = {
        "server": run_server,
        "test": test_setup,
        "install": install_deps,
        "models": download_models,
        "preprocess": preprocess_data,
        "env": create_env,
        "tests": run_tests,
        "lint": lint_code,
        "format": format_code,
        "clean": clean,
        "info": show_info,
        "setup": full_setup,
    }
    
    if args.command in commands:
        commands[args.command]()
    else:
        print(f"❌ Unknown command: {args.command}")
        parser.print_help()

if __name__ == "__main__":
    main()
