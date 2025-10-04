#!/usr/bin/env python3
"""
Skill Gap Analyzer - Backend Server Runner
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
backend_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(backend_root))

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_environment():
    """Check if the environment is properly set up"""
    logger.info("🔍 Checking environment setup...")
    
    # Check if .env file exists
    env_file = project_root / ".env"
    if not env_file.exists():
        logger.warning("⚠️ .env file not found. Using default configurations.")
        logger.info("💡 Create .env file from .env.example for custom configurations")
    
    # Check if required directories exist
    required_dirs = [
        "data",
        "data/raw",
        "data/processed", 
        "backend/uploads",
        "models"
    ]
    
    for dir_path in required_dirs:
        full_path = project_root / dir_path
        if not full_path.exists():
            logger.info(f"📁 Creating directory: {dir_path}")
            full_path.mkdir(parents=True, exist_ok=True)
    
    logger.info("✅ Environment check complete")

def main():
    """Main function to start the server"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SKILL GAP ANALYZER                        ║
    ║                  AI-Powered Career Platform                  ║
    ║                                                              ║
    ║  🚀 Starting FastAPI Backend Server...                      ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Check environment first
        check_environment()
        
        # Import and run the server
        import uvicorn
        from config import Config
        
        logger.info(f"🌐 Server will start at: http://{Config.API_HOST}:{Config.API_PORT}")
        logger.info(f"📚 API Documentation: http://{Config.API_HOST}:{Config.API_PORT}/docs")
        logger.info(f"🏥 Health Check: http://{Config.API_HOST}:{Config.API_PORT}/health")
        
        if Config.DEBUG:
            logger.info("🔧 Running in DEBUG mode - auto-reload enabled")
        
        # Start the server
        uvicorn.run(
            "app.main:app",
            host=Config.API_HOST,
            port=Config.API_PORT,
            reload=Config.DEBUG,
            reload_dirs=[str(backend_root)] if Config.DEBUG else None,
            log_level="info" if Config.DEBUG else "warning",
            access_log=True
        )
        
    except ImportError as e:
        logger.error(f"❌ Import error: {e}")
        logger.error("💡 Make sure all dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
