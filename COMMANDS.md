# 📋 Quick Command Reference

## 🚀 **Start the Project**
```powershell
# Option 1: Automated (Recommended)
python quick-start.py

# Option 2: Manual Backend
cd backend
.\venv\Scripts\activate
python demo_main.py

# Option 3: Manual Frontend
cd frontend
npm start
```

## 🛠️ **Setup Commands**
```powershell
# Backend Setup
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements-demo.txt

# Frontend Setup
cd frontend
npm install
```

## 🌐 **Access Points**
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🧪 **Test Commands**
```powershell
# Frontend Build Test
cd frontend
npm run build

# Backend Test
cd backend
.\venv\Scripts\activate
python demo_main.py

# API Health Test
curl http://localhost:8000/health
```

## 🔧 **Troubleshooting**
```powershell
# Reset Backend
cd backend
Remove-Item -Recurse -Force venv
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements-demo.txt

# Reset Frontend
cd frontend
Remove-Item -Recurse -Force node_modules
npm install

# Check Ports
netstat -ano | findstr :3000
netstat -ano | findstr :8000
```

## ⚡ **One-Line Start**
```powershell
python quick-start.py
```
**That's it!** 🎉
