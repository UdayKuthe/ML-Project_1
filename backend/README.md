# Skill Gap Analyzer - Backend API

## 🎯 Overview

The Skill Gap Analyzer Backend is a comprehensive FastAPI-based REST API that provides intelligent skill gap analysis, resume processing, and course recommendations using advanced machine learning and natural language processing techniques.

## 🚀 Features

### Core Functionality
- **📄 Resume Processing**: Upload and parse PDF, DOCX, DOC, and TXT resume files
- **🧠 AI-Powered Skill Extraction**: Advanced NLP using spaCy and SBERT for skill identification
- **📊 Skill Gap Analysis**: Compare extracted skills against job requirements
- **📈 Interactive Visualizations**: Generate charts and graphs using Plotly
- **🎯 Course Recommendations**: AI-suggested learning paths from multiple platforms
- **🔐 Secure Authentication**: JWT-based authentication with bcrypt password hashing
- **📱 RESTful API**: Complete REST API with comprehensive documentation

### Technology Stack
- **Framework**: FastAPI (Python 3.8+)
- **ML/AI**: spaCy, SBERT, scikit-learn, TensorFlow
- **Database**: MySQL with optimized schemas
- **File Processing**: PyPDF2, python-docx
- **Authentication**: JWT tokens with bcrypt
- **Visualization**: Plotly
- **Testing**: pytest, pytest-asyncio

## 📁 Project Structure

```
backend/
├── app/
│   ├── api/                    # API route handlers
│   │   ├── __init__.py
│   │   ├── auth.py            # Authentication endpoints
│   │   ├── resumes.py         # Resume management endpoints
│   │   ├── skills_jobs.py     # Skills and jobs endpoints
│   │   └── analysis.py        # Analysis endpoints
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py         # Pydantic models for validation
│   ├── services/              # Business logic services
│   │   ├── __init__.py
│   │   ├── data_preprocessor.py
│   │   ├── spacy_trainer.py
│   │   ├── skill_analyzer.py
│   │   └── course_recommender.py
│   ├── utils/                 # Utility functions
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── database.py
│   │   └── file_processing.py
│   └── main.py                # FastAPI application entry point
├── uploads/                   # Uploaded resume files
├── tests/                     # Test suite
├── requirements.txt           # Python dependencies
├── run.py                     # Server startup script
└── README.md                  # This file
```

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- MySQL 8.0+
- Git

### 1. Clone the Repository
```bash
git clone <repository-url>
cd skill-gap-analyzer
```

### 2. Set Up Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
# Navigate to backend directory
cd backend

# Install Python packages
pip install -r requirements.txt

# Download spaCy model
python -m spacy download en_core_web_sm
```

### 4. Database Setup
1. Create a MySQL database named `skill_gap_analyzer`
2. Run the SQL scripts from `../database/` directory
3. Import the sample data using the provided scripts

### 5. Environment Configuration
```bash
# Copy environment template
cp ../.env.example ../.env

# Edit .env file with your configurations
# Required: DATABASE_URL, JWT_SECRET_KEY
```

### 6. Data Preprocessing (Optional)
```bash
# Run data preprocessing if you have custom datasets
python ../scripts/preprocess_data.py
```

## 🚀 Running the Server

### Development Mode
```bash
# Start the development server with auto-reload
python run.py
```

### Production Mode
```bash
# Set environment variables
export DEBUG=False
export API_HOST=0.0.0.0
export API_PORT=8000

# Start production server
python run.py
```

### Using Uvicorn Directly
```bash
# Development
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## 📚 API Documentation

### Interactive Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### API Endpoints

#### System Endpoints
- `GET /` - API root information
- `GET /health` - Health check and system status
- `GET /info` - Detailed API information and statistics

#### Authentication (`/api/v1/auth`)
- `POST /register` - User registration
- `POST /login` - User login
- `GET /profile` - Get user profile
- `POST /refresh` - Refresh JWT token
- `POST /logout` - User logout

#### Resume Management (`/api/v1/resumes`)
- `POST /upload` - Upload resume file
- `GET /` - List user's resumes
- `GET /{resume_id}` - Get specific resume
- `GET /{resume_id}/status` - Check processing status
- `DELETE /{resume_id}` - Delete resume
- `POST /{resume_id}/reprocess` - Reprocess resume

#### Skills & Jobs (`/api/v1/skills-jobs`)
- `GET /skills` - List all skills
- `GET /skills/search` - Search skills
- `GET /skills/trending` - Get trending skills
- `GET /skills/categories` - Get skill categories
- `GET /jobs` - List job professions
- `GET /jobs/search` - Search jobs
- `GET /jobs/{job_id}` - Get job details

#### Analysis (`/api/v1/analysis`)
- `POST /analyze` - Perform skill gap analysis
- `GET /history` - Get analysis history
- `GET /{analysis_id}` - Get specific analysis

## 🔐 Authentication

The API uses JWT (JSON Web Tokens) for authentication:

1. **Register** a new user account via `/api/v1/auth/register`
2. **Login** to receive access and refresh tokens via `/api/v1/auth/login`
3. **Include** the access token in the `Authorization` header: `Bearer <token>`
4. **Refresh** tokens when they expire using `/api/v1/auth/refresh`

### Token Structure
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

## 💾 Database

The API uses MySQL with the following key tables:
- `users` - User accounts and profiles
- `skills` - Skill definitions and categories
- `job_professions` - Job titles and requirements
- `resumes` - Uploaded resume metadata
- `skill_analyses` - Analysis results and history
- `course_recommendations` - Recommended courses

For detailed database schema, see `../database/README.md`.

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_auth.py

# Run with verbose output
pytest -v
```

### Test Structure
```
tests/
├── __init__.py
├── conftest.py              # Test configuration and fixtures
├── test_auth.py            # Authentication tests
├── test_resumes.py         # Resume processing tests
├── test_skills_jobs.py     # Skills and jobs tests
├── test_analysis.py        # Analysis tests
└── test_integration.py     # Integration tests
```

## 📈 Performance & Monitoring

### Health Monitoring
Check system health at `/health`:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-20T10:30:00Z",
  "version": "1.0.0",
  "database_connected": true,
  "services_status": {
    "skill_extraction": "available",
    "skill_analysis": "available",
    "course_recommendations": "available"
  }
}
```

### Logging
- Application logs are written to `app.log`
- Request/response logging with timing information
- Error tracking with stack traces in debug mode

### Performance Tips
- Use pagination for large datasets
- Enable response caching for frequently accessed data
- Monitor database query performance
- Use async processing for heavy ML operations

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `True` |
| `API_HOST` | Server host address | `127.0.0.1` |
| `API_PORT` | Server port | `8000` |
| `DATABASE_URL` | MySQL connection string | Required |
| `JWT_SECRET_KEY` | JWT signing secret | Required |
| `JWT_ACCESS_TOKEN_EXPIRE` | Access token expiration (minutes) | `60` |
| `JWT_REFRESH_TOKEN_EXPIRE` | Refresh token expiration (days) | `30` |
| `UPLOAD_FOLDER` | File upload directory | `uploads` |
| `MAX_FILE_SIZE` | Max upload size (bytes) | `10485760` |

### Model Configuration
```python
# config.py
class Config:
    # ML Model settings
    SPACY_MODEL_PATH = "models/skill_extractor"
    SBERT_MODEL_NAME = "all-MiniLM-L6-v2"
    SKILL_SIMILARITY_THRESHOLD = 0.7
    
    # Training parameters
    TRAIN_ITERATIONS = 100
    DROPOUT_RATE = 0.35
    LEARNING_RATE = 0.001
```

## 🚨 Error Handling

The API provides consistent error responses:

```json
{
  "error": "Error description",
  "detail": "Detailed error message",
  "status_code": 400,
  "timestamp": "2024-01-20T10:30:00Z",
  "path": "/api/v1/endpoint"
}
```

### Common HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `422` - Validation Error
- `500` - Internal Server Error

## 📦 Deployment

### Docker Deployment
```dockerfile
# Dockerfile (to be created)
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["python", "run.py"]
```

### Production Checklist
- [ ] Set `DEBUG=False`
- [ ] Use environment variables for secrets
- [ ] Configure HTTPS with SSL certificates
- [ ] Set up reverse proxy (Nginx)
- [ ] Configure database connection pooling
- [ ] Enable request rate limiting
- [ ] Set up monitoring and logging
- [ ] Configure backup procedures

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints where possible
- Add docstrings for functions and classes
- Keep functions focused and single-purpose

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Troubleshooting

**Database Connection Issues**
```bash
# Check MySQL service
mysql -u root -p -e "SELECT 1"

# Verify database exists
mysql -u root -p -e "SHOW DATABASES LIKE 'skill_gap_analyzer'"
```

**Module Import Errors**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Download spaCy models
python -m spacy download en_core_web_sm
```

**File Upload Issues**
```bash
# Check upload directory permissions
ls -la uploads/

# Create upload directory if missing
mkdir -p uploads
chmod 755 uploads
```

### Getting Help
- Check the [Issues](https://github.com/your-repo/issues) section
- Review the API documentation at `/docs`
- Check application logs in `app.log`
- Contact: support@skillgapanalyzer.com

---

**🎉 Happy Coding!** The Skill Gap Analyzer backend is ready to power your career development platform!
