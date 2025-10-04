# 🎯 Skill Gap Analyzer - AI-Powered Career Development Platform

An intelligent full-stack application that analyzes resumes, identifies skill gaps against job requirements, and provides personalized course recommendations to advance your career.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![React](https://img.shields.io/badge/react-18.0+-blue.svg)
![FastAPI](https://img.shields.io/badge/fastapi-latest-green.svg)

## 🌟 Features

### 🧠 AI-Powered Analysis
- **Resume Processing**: Upload PDF, Word, or text resumes with automatic skill extraction
- **NLP Technology**: Advanced natural language processing using spaCy and SBERT
- **Skill Gap Analysis**: Compare your skills against job requirements with visual insights
- **Machine Learning**: Continuous improvement through ML model training

### 📊 Interactive Visualizations
- **Skill Proficiency Charts**: Radar and bar charts showing your skill levels
- **Gap Analysis**: Visual representation of missing skills and areas for improvement
- **Progress Tracking**: Monitor your skill development over time
- **Export Capabilities**: Save and share your analysis results

### 🎓 Course Recommendations
- **Multi-Platform Support**: Courses from Coursera, Udemy, edX, LinkedIn Learning
- **Personalized Suggestions**: AI-recommended learning paths based on skill gaps
- **Smart Filtering**: Filter by price, level, provider, and duration
- **Learning Paths**: Structured progression for skill development

### 💼 Professional Tools
- **Resume Management**: Upload, organize, and track multiple resumes
- **Job Matching**: Compare skills against specific job descriptions
- **Career Insights**: Industry trends and in-demand skills analysis
- **Progress Analytics**: Track your learning journey and achievements

## 🏗️ Architecture

```
skill-gap-analyzer/
├── backend/                 # FastAPI Backend
│   ├── app/
│   │   ├── api/            # API endpoints
│   │   ├── models/         # Data models
│   │   ├── services/       # Business logic
│   │   └── utils/          # Utilities
│   └── requirements.txt
├── frontend/               # React Frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API services
│   │   └── utils/          # Helper functions
│   └── package.json
├── database/               # Database schemas
├── data/                   # Datasets and models
├── scripts/                # Utility scripts
└── models/                 # ML models
```

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+** - [Download](https://python.org)
- **Node.js 16+** - [Download](https://nodejs.org)
- **MySQL 8.0+** - [Download](https://mysql.com)
- **Git** - [Download](https://git-scm.com)

### 1. Clone Repository
```bash
git clone <repository-url>
cd skill-gap-analyzer
```

### 2. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configurations
# Required: DATABASE_URL, JWT_SECRET_KEY
```

### 3. Database Setup
```bash
# Create MySQL database
mysql -u root -p -e "CREATE DATABASE skill_gap_analyzer;"

# Run database scripts
mysql -u root -p skill_gap_analyzer < database/schema.sql
mysql -u root -p skill_gap_analyzer < database/sample_data.sql
```

### 4. Backend Setup
```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy model
python -m spacy download en_core_web_sm

# Run setup test
python test_setup.py
```

### 5. Frontend Setup
```bash
# Navigate to frontend
cd frontend

# Install dependencies
npm install

# Start development server (optional)
npm start
```

### 6. Start Application
```bash
# From project root, start both servers
python dev-start.py
```

## 🌐 Access the Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 📱 Usage Guide

### 1. User Registration
1. Navigate to http://localhost:3000
2. Click "Get Started" or "Register"
3. Fill in your details with a strong password
4. Verify email and login

### 2. Resume Upload
1. Go to the "Resumes" section
2. Click "Upload Resume"
3. Drag & drop or select your resume file (PDF, DOCX, DOC, TXT)
4. Wait for AI processing to extract skills

### 3. Skill Gap Analysis
1. Navigate to "Analysis"
2. Select a processed resume
3. Choose target job profession
4. Click "Start Analysis"
5. Review interactive charts and recommendations

### 4. Course Recommendations
1. Visit "Recommendations" section
2. Add skills you want to learn
3. Filter by provider, level, and price
4. Browse personalized course suggestions
5. Click "Enroll Now" to access courses

### 5. Dashboard Insights
- View your progress and statistics
- Track recent analyses and activities
- Monitor trending skills in your field
- Access quick actions for common tasks

## 🧪 API Documentation

### Authentication Endpoints
```
POST /api/v1/auth/register    # User registration
POST /api/v1/auth/login       # User login
GET  /api/v1/auth/profile     # Get user profile
POST /api/v1/auth/refresh     # Refresh JWT token
```

### Resume Management
```
POST   /api/v1/resumes/upload      # Upload resume
GET    /api/v1/resumes             # List resumes
GET    /api/v1/resumes/{id}        # Get resume details
DELETE /api/v1/resumes/{id}        # Delete resume
POST   /api/v1/resumes/{id}/reprocess # Reprocess resume
```

### Analysis & Recommendations
```
POST /api/v1/analysis/analyze        # Perform skill gap analysis
GET  /api/v1/analysis/history        # Get analysis history
GET  /api/v1/analysis/{id}           # Get specific analysis
GET  /api/v1/skills-jobs/skills      # List skills
GET  /api/v1/skills-jobs/jobs        # List job professions
```

For complete API documentation, visit: http://localhost:8000/docs

## 🛠️ Development

### Backend Development
```bash
cd backend

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v

# Run with auto-reload
python run.py

# Code formatting
python dev.py format

# Linting
python dev.py lint
```

### Frontend Development
```bash
cd frontend

# Start development server
npm start

# Run tests
npm test

# Build for production
npm run build

# Code formatting
npm run format

# Linting
npm run lint
```

### Database Management
```bash
# Backup database
mysqldump -u root -p skill_gap_analyzer > backup.sql

# Restore database
mysql -u root -p skill_gap_analyzer < backup.sql

# Run migrations (if any)
python scripts/migrate.py
```

## 🧪 Testing

### Backend Tests
```bash
cd backend
python -m pytest tests/ -v --cov=app
```

### Frontend Tests
```bash
cd frontend
npm test
npm run test:coverage
```

### Integration Tests
```bash
# Test full workflow
python scripts/integration_test.py
```

## 📊 Machine Learning Models

### Skill Extraction Model
- **Technology**: spaCy NER (Named Entity Recognition)
- **Training Data**: Resume corpus with skill annotations
- **Accuracy**: ~85% skill extraction accuracy
- **Update Frequency**: Monthly retraining

### Skill Similarity Model
- **Technology**: SBERT (Sentence-BERT)
- **Model**: all-MiniLM-L6-v2
- **Purpose**: Semantic skill matching and clustering
- **Threshold**: 0.7 similarity score for matching

### Recommendation Engine
- **Algorithm**: Collaborative filtering + Content-based
- **Features**: Skill relevance, user preferences, course ratings
- **Data Sources**: Multiple course platforms APIs
- **Update**: Real-time recommendation generation

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=mysql://user:password@localhost:3306/skill_gap_analyzer

# Authentication
JWT_SECRET_KEY=your-super-secret-jwt-key
JWT_ACCESS_TOKEN_EXPIRE=60
JWT_REFRESH_TOKEN_EXPIRE=43200

# API Settings
API_HOST=127.0.0.1
API_PORT=8000
DEBUG=True

# File Upload
UPLOAD_FOLDER=uploads
MAX_FILE_SIZE=10485760

# External APIs
COURSERA_API_KEY=your-coursera-api-key
UDEMY_API_KEY=your-udemy-api-key
EDX_API_KEY=your-edx-api-key
```

### Model Configuration
```python
# config.py
SPACY_MODEL_PATH = "models/skill_extractor"
SBERT_MODEL_NAME = "all-MiniLM-L6-v2"
SKILL_SIMILARITY_THRESHOLD = 0.7
TRAIN_ITERATIONS = 100
```

## 📦 Deployment

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Scale services
docker-compose up -d --scale api=3
```

### Production Setup
```bash
# Backend (using Gunicorn)
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker

# Frontend (build and serve)
npm run build
npx serve -s build -l 3000

# Database (production MySQL)
# Configure connection pooling and optimization
```

### Environment-Specific Configs
- **Development**: Auto-reload, debug mode, local database
- **Staging**: Production-like setup with test data
- **Production**: Optimized for performance and security

## 🔒 Security

### Authentication
- JWT tokens with refresh mechanism
- Bcrypt password hashing
- Rate limiting on auth endpoints
- Session management

### Data Protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- CSRF protection
- File upload validation

### API Security
- HTTPS enforcement in production
- CORS configuration
- Request size limits
- API rate limiting

## 📈 Performance Optimization

### Backend Optimization
- Database query optimization with indexes
- Caching with Redis (optional)
- Background task processing
- Connection pooling

### Frontend Optimization
- Code splitting and lazy loading
- Image optimization
- Bundle size optimization
- Progressive Web App (PWA) features

### ML Model Optimization
- Model quantization for faster inference
- Batch processing for multiple resumes
- Caching of frequently used embeddings
- Asynchronous model loading

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** and add tests
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 for Python code
- Use ESLint and Prettier for JavaScript
- Write tests for new features
- Update documentation
- Use meaningful commit messages

## 🐛 Troubleshooting

### Common Issues

**Database Connection Error**
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
python -m spacy download en_core_web_sm
```

**Frontend Build Issues**
```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

**Model Loading Issues**
```bash
# Download required models
python -c "import spacy; spacy.cli.download('en_core_web_sm')"
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
```

### Getting Help
- Check the [Issues](https://github.com/your-repo/issues) section
- Review API documentation at `/docs`
- Check application logs in `backend/app.log`
- Run setup tests: `python backend/test_setup.py`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **spaCy** for NLP processing
- **Sentence Transformers** for semantic similarity
- **FastAPI** for the robust backend framework
- **React** for the dynamic frontend
- **Tailwind CSS** for beautiful styling
- **Chart.js** for data visualizations
- **Course Providers** for educational content APIs

## 📞 Support

- **Email**: support@skillgapanalyzer.com
- **Documentation**: https://docs.skillgapanalyzer.com
- **Community**: https://community.skillgapanalyzer.com
- **Issues**: https://github.com/your-repo/issues

---

**🎉 Ready to bridge your skill gaps and advance your career?**

Start your journey with the Skill Gap Analyzer today!

```bash
python dev-start.py
```

**Happy Learning! 🚀📚**
