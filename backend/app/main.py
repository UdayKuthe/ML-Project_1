"""
Main FastAPI application for Skill Gap Analyzer
"""

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
import logging
import time
from datetime import datetime
from contextlib import asynccontextmanager
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from config import Config
from app.models.schemas import ErrorResponse, HealthCheckResponse

# Import API routers
from app.api.auth import router as auth_router
from app.api.resumes import router as resumes_router
from app.api.skills_jobs import router as skills_jobs_router
from app.api.analysis import router as analysis_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("🚀 Starting Skill Gap Analyzer API...")
    
    # Test database connection
    try:
        from app.utils.database import db_manager
        with db_manager.get_db_cursor() as cursor:
            cursor.execute("SELECT 1")
        logger.info("✅ Database connection successful")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
    
    # Initialize ML models (in background)
    try:
        from app.services.spacy_trainer import SkillExtractor
        from app.services.skill_analyzer import SkillGapAnalyzer
        
        # These will be loaded lazily when first needed
        logger.info("🧠 ML models will be loaded on first use")
    except Exception as e:
        logger.warning(f"⚠️ ML models initialization warning: {e}")
    
    logger.info("✅ Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down Skill Gap Analyzer API...")
    logger.info("✅ Application shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="Skill Gap Analyzer API",
    description="""
    ## Skill Gap Analyzer - AI-Powered Career Development Platform
    
    A comprehensive API for analyzing skill gaps in resumes against job requirements,
    with AI-powered recommendations and course suggestions.
    
    ### Features:
    - 📄 **Resume Processing**: Upload and extract skills from PDF/Word documents
    - 🧠 **AI-Powered Analysis**: Advanced NLP for skill extraction and matching
    - 📊 **Gap Analysis**: Compare skills against job requirements
    - 📈 **Visualizations**: Interactive charts and graphs
    - 🎯 **Course Recommendations**: AI-suggested learning paths
    - 📱 **RESTful API**: Complete REST API with authentication
    
    ### Technology Stack:
    - **Backend**: FastAPI, Python 3.8+
    - **ML/AI**: spaCy, SBERT, scikit-learn, TensorFlow
    - **Database**: MySQL with optimized schemas
    - **Authentication**: JWT tokens with bcrypt
    """,
    version="1.0.0",
    terms_of_service="https://skillgapanalyzer.com/terms",
    contact={
        "name": "Skill Gap Analyzer Support",
        "url": "https://skillgapanalyzer.com/support",
        "email": "support@skillgapanalyzer.com",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
    docs_url="/docs" if Config.DEBUG else None,
    redoc_url="/redoc" if Config.DEBUG else None
)

# Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"] if Config.DEBUG else ["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

if not Config.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["yourdomain.com", "*.yourdomain.com"]
    )

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests"""
    start_time = time.time()
    
    # Log request
    logger.info(f"📥 {request.method} {request.url.path} - Client: {request.client.host if request.client else 'Unknown'}")
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    # Log response
    logger.info(f"📤 {request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.3f}s")
    
    # Add processing time to response headers
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# Global exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Global HTTP exception handler"""
    logger.error(f"❌ HTTP {exc.status_code}: {exc.detail} - Path: {request.url.path}")
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        }
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled exceptions"""
    logger.error(f"💥 Unhandled exception: {str(exc)} - Path: {request.url.path}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": str(exc) if Config.DEBUG else "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        }
    )

# Include API routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(resumes_router, prefix="/api/v1")
app.include_router(skills_jobs_router, prefix="/api/v1")
app.include_router(analysis_router, prefix="/api/v1")

# Health check endpoint
@app.get("/health", 
         response_model=HealthCheckResponse,
         tags=["System"],
         summary="Health Check",
         description="Check the health status of the API and its dependencies")
async def health_check():
    """
    Health check endpoint to verify API status and dependencies
    
    Returns system status, database connectivity, and service health
    """
    try:
        # Check database connection
        database_connected = True
        try:
            from app.utils.database import db_manager
            with db_manager.get_db_cursor() as cursor:
                cursor.execute("SELECT 1")
        except Exception as e:
            database_connected = False
            logger.error(f"Database health check failed: {e}")
        
        # Check ML services
        services_status = {}
        
        try:
            # Test if spaCy model can be loaded
            from app.services.spacy_trainer import SkillExtractor
            services_status["skill_extraction"] = "available"
        except Exception:
            services_status["skill_extraction"] = "unavailable"
        
        try:
            # Test if skill analyzer can be initialized
            from app.services.skill_analyzer import SkillGapAnalyzer
            services_status["skill_analysis"] = "available"
        except Exception:
            services_status["skill_analysis"] = "unavailable"
        
        try:
            # Test course recommendation service
            from app.services.course_recommender import CourseRecommendationEngine
            services_status["course_recommendations"] = "available"
        except Exception:
            services_status["course_recommendations"] = "unavailable"
        
        # Determine overall status
        overall_status = "healthy" if database_connected else "degraded"
        if not any(status == "available" for status in services_status.values()):
            overall_status = "unhealthy"
        
        return HealthCheckResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            version="1.0.0",
            database_connected=database_connected,
            services_status=services_status
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthCheckResponse(
            status="unhealthy",
            timestamp=datetime.utcnow(),
            version="1.0.0",
            database_connected=False,
            services_status={"error": str(e)}
        )

# Root endpoint
@app.get("/", 
         tags=["System"],
         summary="API Root",
         description="Root endpoint with API information")
async def root():
    """
    API root endpoint with basic information
    """
    return {
        "message": "Welcome to Skill Gap Analyzer API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/health",
        "api_base": "/api/v1",
        "endpoints": {
            "authentication": "/api/v1/auth",
            "resumes": "/api/v1/resumes",
            "skills_and_jobs": "/api/v1/skills-jobs",
            "analysis": "/api/v1/analysis"
        }
    }

# API Info endpoint
@app.get("/info", 
         tags=["System"],
         summary="API Information")
async def api_info():
    """
    Get detailed API information and statistics
    """
    try:
        from app.utils.database import db_manager
        
        # Get database statistics
        stats = {}
        try:
            with db_manager.get_db_cursor() as cursor:
                # Count users
                cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_active = TRUE")
                stats["active_users"] = cursor.fetchone()["count"]
                
                # Count skills
                cursor.execute("SELECT COUNT(*) as count FROM skills")
                stats["total_skills"] = cursor.fetchone()["count"]
                
                # Count job professions
                cursor.execute("SELECT COUNT(*) as count FROM job_professions")
                stats["total_jobs"] = cursor.fetchone()["count"]
                
                # Count analyses
                cursor.execute("SELECT COUNT(*) as count FROM skill_analyses")
                stats["total_analyses"] = cursor.fetchone()["count"]
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            stats = {"error": "Could not retrieve statistics"}
        
        return {
            "api_name": "Skill Gap Analyzer API",
            "version": "1.0.0",
            "description": "AI-powered skill gap analysis and career development platform",
            "features": [
                "Resume skill extraction",
                "Job requirement analysis",
                "Skill gap identification",
                "Course recommendations",
                "Career path visualization"
            ],
            "statistics": stats,
            "technology_stack": {
                "framework": "FastAPI",
                "ml_frameworks": ["spaCy", "scikit-learn", "TensorFlow", "SBERT"],
                "database": "MySQL",
                "authentication": "JWT",
                "file_processing": ["PyPDF2", "python-docx"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error in API info endpoint: {e}")
        return {"error": "Could not retrieve API information"}

# Custom OpenAPI schema
def custom_openapi():
    """Custom OpenAPI schema with enhanced documentation"""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="Skill Gap Analyzer API",
        version="1.0.0",
        description=app.description,
        routes=app.routes,
    )
    
    # Add custom schema information
    openapi_schema["info"]["x-logo"] = {
        "url": "https://skillgapanalyzer.com/logo.png"
    }
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Development server
if __name__ == "__main__":
    import uvicorn
    
    logger.info("🚀 Starting Skill Gap Analyzer API in development mode...")
    
    uvicorn.run(
        "main:app",
        host=Config.API_HOST,
        port=Config.API_PORT,
        reload=Config.DEBUG,
        log_level="info" if Config.DEBUG else "warning",
        access_log=True
    )
