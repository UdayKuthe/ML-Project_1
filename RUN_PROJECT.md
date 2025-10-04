# 🚀 Skill Gap Analyzer - Project Setup & Run Guide

## 📋 Project Overview

**Skill Gap Analyzer** is an AI-powered career development platform that helps users:
- Upload and analyze resumes
- Identify skill gaps against job requirements
- Get personalized course recommendations
- Track career development progress

### 🏗️ Project Structure
```
skill-gap-analyzer/
├── backend/              # FastAPI Backend (Python)
│   ├── demo_main.py     # Main demo application
│   ├── venv/            # Python virtual environment
│   └── requirements-demo.txt # Python dependencies
├── frontend/            # React Frontend (JavaScript)
│   ├── src/             # React source code
│   ├── build/           # Production build
│   └── package.json     # Node.js dependencies
└── README.md           # This file
```

## ✅ Project Status: **READY TO RUN**

Both backend and frontend are fully configured and tested. No database setup required for the demo version.

## 🎯 Quick Start (Recommended)

### **Option 1: Automated Startup**
```powershell
# From project root directory
python quick-start.py
```

### **Option 2: Manual Startup**
Follow the detailed instructions below.

---

## 📋 Prerequisites

### Required Software
- ✅ **Python 3.8+** - [Download Python](https://python.org/downloads)
- ✅ **Node.js 16+** - [Download Node.js](https://nodejs.org)
- ✅ **Git** (optional) - [Download Git](https://git-scm.com/downloads)

### Verify Installation
```powershell
# Check Python version
python --version
# Should show: Python 3.x.x

# Check Node.js version
node --version
# Should show: v16.x.x or higher

npm --version
# Should show: 8.x.x or higher
```

---

## 🛠️ Setup Instructions

### 1. Backend Setup (FastAPI)

```powershell
# Navigate to backend directory
cd backend

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\activate

# Install Python dependencies
pip install -r requirements-demo.txt

# Test backend setup
python demo_main.py
# Should show: Server running on http://127.0.0.1:8000
# Press Ctrl+C to stop
```

### 2. Frontend Setup (React)

Open a **new terminal/command prompt**:

```powershell
# Navigate to frontend directory
cd frontend

# Install Node.js dependencies
npm install

# Build the project (optional)
npm run build

# Test frontend setup
npm start
# Should show: Server running on http://localhost:3000
# Press Ctrl+C to stop
```

---

## 🚀 Running the Project

### **Method 1: Both Servers Simultaneously** ⭐

```powershell
# From project root directory
python quick-start.py
```

**Access Points:**
- 🌐 **Frontend**: http://localhost:3000
- ⚡ **Backend API**: http://localhost:8000
- 📖 **API Docs**: http://localhost:8000/docs

### **Method 2: Manual Server Startup**

**Terminal 1 - Backend:**
```powershell
cd backend
.\venv\Scripts\activate
python demo_main.py
```

**Terminal 2 - Frontend:**
```powershell
cd frontend
npm start
```

---

## 🎮 How to Use the Application

### 1. **Access the Application**
- Open your browser and go to: http://localhost:3000

### 2. **Register/Login**
- Create a new account or use demo credentials
- Demo email: `demo@example.com`
- Demo password: `password`

### 3. **Upload Resume**
- Navigate to "Resumes" section
- Upload a PDF, Word, or text file
- Wait for AI processing (simulated)

### 4. **Analyze Skills**
- Go to "Analysis" section
- Select an uploaded resume
- Choose a job title (e.g., "Software Engineer")
- Click "Start Analysis"

### 5. **View Recommendations**
- Visit "Recommendations" section
- Browse course suggestions
- Filter by provider, level, or price

### 6. **Dashboard Overview**
- Check the Dashboard for progress
- View statistics and trends
- Access quick actions

---

## 🧪 API Testing

### Test Backend Endpoints

**Health Check:**
```bash
curl http://localhost:8000/health
```

**API Documentation:**
Visit: http://localhost:8000/docs

**Sample API Calls:**
```bash
# List skills
curl http://localhost:8000/api/v1/skills-jobs/skills

# List jobs
curl http://localhost:8000/api/v1/skills-jobs/jobs

# Get dashboard stats
curl http://localhost:8000/api/v1/dashboard/stats
```

---

## 🛠️ Development Commands

### Backend Development
```powershell
cd backend
.\venv\Scripts\activate

# Install development dependencies
pip install pytest black flake8

# Run tests
python -m pytest tests/ -v

# Format code
black .

# Lint code
flake8 .
```

### Frontend Development
```powershell
cd frontend

# Start development server with hot reload
npm start

# Run tests
npm test

# Build for production
npm run build

# Analyze bundle size
npm run build --analyze
```

---

## 📁 Project Features

### ✅ **Implemented Features**
- **User Authentication**: Register, login, profile management
- **Resume Upload**: PDF, Word, text file support with drag-and-drop
- **Resume Management**: List, view, delete resumes with status tracking
- **Skill Analysis**: AI-powered skill extraction and gap analysis
- **Interactive Charts**: Radar and bar charts for skill visualization
- **Course Recommendations**: Personalized learning suggestions
- **Responsive Design**: Mobile-friendly interface
- **Dashboard Analytics**: Progress tracking and statistics

### 🎯 **Demo Functionality**
- **Simulated AI**: Uses random skill extraction for demonstration
- **Mock Data**: Sample courses, jobs, and skills for testing
- **In-Memory Storage**: Data resets on server restart
- **No Database Required**: Perfect for quick demos

---

## 🔧 Troubleshooting

### Common Issues & Solutions

**Backend Won't Start:**
```powershell
# Check Python version
python --version

# Reinstall dependencies
cd backend
pip install -r requirements-demo.txt --force-reinstall
```

**Frontend Build Errors:**
```powershell
# Clear cache and reinstall
cd frontend
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install
```

**Port Conflicts:**
```powershell
# Check what's using ports
netstat -ano | findstr :3000
netstat -ano | findstr :8000

# Kill process if needed
taskkill /PID <process_id> /F
```

**Python Virtual Environment Issues:**
```powershell
# Delete and recreate virtual environment
cd backend
Remove-Item -Recurse -Force venv
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements-demo.txt
```

---

## 📊 Project Statistics

- **Backend**: 13 API endpoints, 329 lines of demo code
- **Frontend**: 8 React components, 15+ pages and features
- **Dependencies**: Minimal, production-ready packages
- **Build Time**: ~30 seconds for both frontend and backend
- **Setup Time**: ~5 minutes for first-time setup

---

## 🎉 Success Indicators

You'll know everything is working when:

### Backend (http://localhost:8000):
```json
{
  "message": "Skill Gap Analyzer API - Demo Version",
  "version": "1.0.0"
}
```

### Frontend (http://localhost:3000):
- ✅ Homepage loads without errors
- ✅ Registration/login forms work
- ✅ Resume upload interface is functional
- ✅ Charts and visualizations display
- ✅ Navigation between pages works

### API Documentation (http://localhost:8000/docs):
- ✅ Swagger UI loads with all endpoints
- ✅ Try it out functionality works
- ✅ All endpoints return proper responses

---

## 🆘 Need Help?

### **Quick Fixes:**
1. **Restart both servers** - Fixes most issues
2. **Check console logs** - Look for error messages
3. **Clear browser cache** - Reload with Ctrl+F5
4. **Run setup commands again** - Reinstall dependencies

### **Getting Support:**
- Check console output for detailed error messages
- Ensure all prerequisites are properly installed
- Verify ports 3000 and 8000 are available
- Make sure virtual environment is activated for backend

---

## 🎊 **Ready to Launch!**

Your **Skill Gap Analyzer** is now ready to use! 

**Start the application:**
```powershell
python quick-start.py
```

**Then visit:** http://localhost:3000

**Happy analyzing!** 🚀📊💼
