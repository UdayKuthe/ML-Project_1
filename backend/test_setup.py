#!/usr/bin/env python3
"""
Quick Setup Test for Skill Gap Analyzer Backend API
"""

import sys
import os
from pathlib import Path
import importlib.util

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test if all required modules can be imported"""
    print("🧪 Testing module imports...")
    
    modules_to_test = [
        ("config", "Configuration"),
        ("app.models.schemas", "Pydantic schemas"),
        ("app.utils.database", "Database utilities"),
        ("app.utils.auth", "Authentication utilities"),
        ("app.utils.file_processing", "File processing utilities"),
        ("app.services.data_preprocessor", "Data preprocessor"),
        ("app.services.spacy_trainer", "spaCy trainer"),
        ("app.services.skill_analyzer", "Skill analyzer"),
        ("app.services.course_recommender", "Course recommender"),
        ("app.api.auth", "Auth API"),
        ("app.api.resumes", "Resume API"),
        ("app.api.skills_jobs", "Skills/Jobs API"),
        ("app.api.analysis", "Analysis API"),
    ]
    
    success_count = 0
    total_count = len(modules_to_test)
    
    for module_name, description in modules_to_test:
        try:
            importlib.import_module(module_name)
            print(f"  ✅ {description}")
            success_count += 1
        except ImportError as e:
            print(f"  ❌ {description} - Import Error: {e}")
        except Exception as e:
            print(f"  ⚠️ {description} - Warning: {e}")
    
    print(f"\n📊 Import Test Results: {success_count}/{total_count} modules imported successfully")
    return success_count == total_count

def test_dependencies():
    """Test if all required dependencies are installed"""
    print("\n🔍 Testing dependencies...")
    
    dependencies = [
        ("fastapi", "FastAPI framework"),
        ("uvicorn", "ASGI server"),
        ("pydantic", "Data validation"),
        ("pymysql", "MySQL connector"),
        ("bcrypt", "Password hashing"),
        ("python_jose", "JWT tokens"),
        ("python_multipart", "File uploads"),
        ("python_docx", "Word document processing"),
        ("PyPDF2", "PDF processing"),
        ("spacy", "NLP library"),
        ("scikit_learn", "Machine learning"),
        ("sentence_transformers", "SBERT embeddings"),
        ("plotly", "Visualizations"),
        ("python_dotenv", "Environment variables"),
    ]
    
    success_count = 0
    total_count = len(dependencies)
    
    for package, description in dependencies:
        try:
            importlib.import_module(package)
            print(f"  ✅ {description}")
            success_count += 1
        except ImportError:
            print(f"  ❌ {description} - Not installed")
    
    print(f"\n📊 Dependency Test Results: {success_count}/{total_count} packages available")
    return success_count >= (total_count * 0.8)  # 80% threshold

def test_directories():
    """Test if required directories exist"""
    print("\n📁 Testing directory structure...")
    
    required_dirs = [
        "app",
        "app/api",
        "app/models",
        "app/services",
        "app/utils",
        "../data",
        "../data/raw",
        "../models",
    ]
    
    success_count = 0
    total_count = len(required_dirs)
    
    for dir_path in required_dirs:
        full_path = Path(__file__).parent / dir_path
        if full_path.exists() and full_path.is_dir():
            print(f"  ✅ {dir_path}")
            success_count += 1
        else:
            print(f"  ❌ {dir_path} - Missing")
    
    print(f"\n📊 Directory Test Results: {success_count}/{total_count} directories found")
    return success_count >= (total_count * 0.8)

def test_config():
    """Test configuration loading"""
    print("\n⚙️ Testing configuration...")
    
    try:
        from config import Config
        print(f"  ✅ Configuration loaded")
        print(f"  📍 API Host: {Config.API_HOST}")
        print(f"  🔌 API Port: {Config.API_PORT}")
        print(f"  🐛 Debug Mode: {Config.DEBUG}")
        print(f"  📁 Upload Folder: {Config.UPLOAD_FOLDER}")
        return True
    except Exception as e:
        print(f"  ❌ Configuration error: {e}")
        return False

def test_main_app():
    """Test if the main FastAPI app can be created"""
    print("\n🚀 Testing FastAPI app creation...")
    
    try:
        from app.main import app
        print(f"  ✅ FastAPI app created successfully")
        print(f"  📋 Title: {app.title}")
        print(f"  📝 Version: {app.version}")
        print(f"  🛣️ Routes: {len(app.routes)} routes registered")
        return True
    except Exception as e:
        print(f"  ❌ FastAPI app creation failed: {e}")
        return False

def main():
    """Run all tests"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                     SETUP TEST SUITE                        ║
    ║              Skill Gap Analyzer Backend API                 ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Directories", test_directories),
        ("Configuration", test_config),
        ("Module Imports", test_imports),
        ("FastAPI App", test_main_app),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Running {test_name} Test")
        print(f"{'='*60}")
        
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n📊 Overall Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Your setup is ready.")
        print("💡 You can now start the server with: python run.py")
    elif passed >= total * 0.8:
        print("\n⚠️ Most tests passed. Some optional features may not work.")
        print("💡 You can try starting the server with: python run.py")
    else:
        print("\n❌ Multiple tests failed. Please check your setup.")
        print("💡 Review the error messages above and fix the issues.")
    
    return passed >= total * 0.8

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
