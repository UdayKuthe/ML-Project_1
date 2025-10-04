# 🚀 Quick Setup Guide - Skill Gap Analyzer

## 📋 Prerequisites Checklist

Before running the project, ensure you have:

### Required Software
- ✅ **Python 3.8+** - [Download Python](https://python.org/downloads)
- ✅ **Node.js 16+** - [Download Node.js](https://nodejs.org)
- ✅ **MySQL 8.0+** - [Download MySQL](https://dev.mysql.com/downloads/mysql)
- ✅ **Git** - [Download Git](https://git-scm.com/downloads)

### Verify Installation
```powershell
# Check Python version
python --version

# Check Node.js version  
node --version
npm --version

# Check MySQL
mysql --version

# Check Git
git --version
```

## 🎯 Option 1: Quick Start (Recommended)

### Step 1: Setup Environment
```powershell
# Navigate to project directory
cd "D:\ML PROJECT\skill-gap-analyzer"

# Copy environment file
copy .env.example .env
```

### Step 2: Configure Database
```powershell
# Start MySQL service (if not running)
# Windows: Services → MySQL → Start

# Create database
mysql -u root -p
```

In MySQL console:
```sql
CREATE DATABASE skill_gap_analyzer;
USE skill_gap_analyzer;
source database/schema.sql;
source database/import_actual_data.sql;
EXIT;
```

### Step 3: Backend Setup
```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy model
python -m spacy download en_core_web_sm

# Test setup
python test_setup.py
```

### Step 4: Frontend Setup
```powershell
# Navigate to frontend (new terminal)
cd frontend

# Install dependencies
npm install

# Verify installation
npm list
```

### Step 5: Launch Application
```powershell
# From project root directory
python dev-start.py
```

🎉 **That's it! Your application should now be running!**

## 🌐 Access Your Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🎯 Option 2: Manual Start

### Terminal 1 - Backend
```powershell
cd backend
.\venv\Scripts\activate
python run.py
```

### Terminal 2 - Frontend
```powershell
cd frontend
npm start
```

## 🎯 Option 3: Docker (Advanced)

```powershell
# Make sure Docker is installed and running
docker --version

# Start with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop containers
docker-compose down
```

## 🛠️ Troubleshooting

### Database Connection Issues
```powershell
# Check if MySQL is running
Get-Service MySQL*

# Start MySQL service
Start-Service MySQL80  # Or your MySQL service name

# Test connection
mysql -u root -p -e "SELECT 1"
```

### Python Environment Issues
```powershell
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Download spaCy model again
python -m spacy download en_core_web_sm
```

### Node.js Issues
```powershell
# Clear cache and reinstall
Remove-Item -Recurse -Force node_modules
Remove-Item package-lock.json
npm install
```

### Port Conflicts
```powershell
# Check what's using port 3000
netstat -ano | findstr :3000

# Check what's using port 8000
netstat -ano | findstr :8000

# Kill process if needed (replace PID)
taskkill /PID <process_id> /F
```

## 📝 Configuration

### Edit .env file (if needed)
```bash
# Database
DATABASE_URL=mysql://root:password@localhost:3306/skill_gap_analyzer

# JWT Secret (change this!)
JWT_SECRET_KEY=your-super-secret-key-here

# API Settings
API_HOST=127.0.0.1
API_PORT=8000
DEBUG=True
```

## ✅ Success Indicators

You'll know it's working when you see:

### Backend Console:
```
INFO:     Started server process [xxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Frontend Console:
```
webpack compiled successfully!

You can now view skill-gap-analyzer in the browser.
Local:            http://localhost:3000
On Your Network:  http://192.168.x.x:3000
```

### Browser Test:
1. Visit http://localhost:3000 - Should show homepage
2. Visit http://localhost:8000/docs - Should show API documentation
3. Register a new user account
4. Upload a sample resume
5. Try the analysis feature

## 🎉 Next Steps

Once running successfully:

1. **Register Account**: Create your user account
2. **Upload Resume**: Test with a sample PDF/Word resume
3. **Run Analysis**: Try the skill gap analysis feature
4. **Browse Courses**: Explore course recommendations
5. **Check Dashboard**: View your progress and statistics

## 🆘 Need Help?

If you encounter issues:

1. Check the troubleshooting section above
2. Verify all prerequisites are installed
3. Ensure MySQL service is running
4. Check for port conflicts
5. Review console error messages
6. Run `python backend/test_setup.py` to verify backend
7. Check `backend/app.log` for detailed error logs

---

**🎊 Happy coding! Your AI-powered career development platform awaits! 🚀**
