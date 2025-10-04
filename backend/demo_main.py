#!/usr/bin/env python3
"""
Skill Gap Analyzer - Demo Version
FastAPI backend with basic functionality (without ML dependencies)
"""

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
import uvicorn
import json
from datetime import datetime, timedelta

# Initialize FastAPI app
app = FastAPI(
    title="Skill Gap Analyzer API - Demo",
    description="AI-powered career development platform (Demo Version)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for demo
users_db = {}
resumes_db = {}
analyses_db = {}

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserProfile(BaseModel):
    id: int
    email: str
    full_name: str
    created_at: datetime

class ResumeUpload(BaseModel):
    filename: str
    content: str
    file_type: str

class ResumeInfo(BaseModel):
    id: int
    filename: str
    status: str
    upload_date: datetime
    extracted_skills: List[str] = []

class AnalysisRequest(BaseModel):
    resume_id: int
    job_title: str

class AnalysisResult(BaseModel):
    id: int
    resume_id: int
    job_title: str
    overall_score: float
    strong_skills: List[str]
    missing_skills: List[str]
    recommended_courses: List[Dict[str, Any]]
    analysis_date: datetime

# Basic skill extraction function
def extract_skills_from_text(text: str) -> list:
    """Extract skills from text content using precise pattern matching"""
    
    import re
    
    # Define precise skill patterns with word boundaries to avoid false positives
    skill_patterns = {
        # Programming Languages - exact matches with better patterns
        r'\bjava\b(?!script)': 'Java',  # Java but not JavaScript
        r'c\+\+': 'C++',  # C++ without strict word boundaries
        r'\bc#\b': 'C#',
        r'\b(?<!\w)c(?!\+|#|ss|n|ertif|omputer|loud)\b': 'C',  # C but not C++, C#, CSS, CN, etc.
        r'\bjavascript\b': 'JavaScript',
        r'\bjs\b(?!on)': 'JavaScript',  # js but not json
        r'\btypescript\b': 'TypeScript',
        r'\bpython\b': 'Python',
        r'\bdart\b': 'Dart',
        r'\bphp\b': 'PHP',
        r'\bruby\b': 'Ruby',
        r'\bkotlin\b': 'Kotlin',
        r'\bswift\b': 'Swift',
        r'\bscala\b': 'Scala',
        r'\bgo\b(?!ogle)': 'Go',  # Go but not Google
        r'\br\b(?!eact)': 'R',  # R but not React
        
        # Web Technologies with more precise patterns
        r'\bhtml\b': 'HTML',
        r'\bcss\b(?!\.)': 'CSS',  # CSS but not .css file extension
        r'\breact(?:\.js)?\b': 'React.js',
        r'\bnode(?:\.js)?\b': 'Node.js',
        r'\bexpress(?:\.js)?\b': 'Express.js',
        r'\bangular\b': 'Angular',
        r'\bvue(?:\.js)?\b': 'Vue.js',
        r'\bnext(?:\.js)?\b': 'Next.js',
        r'\bmern\s+stack\b': 'MERN Stack',
        r'\bbootstrap\b': 'Bootstrap',
        r'\btailwind\s+css\b': 'Tailwind CSS',
        r'\bsass\b': 'SASS',
        r'\bscss\b': 'SCSS',
        
        # Databases
        r'\bmysql\b': 'MySQL',
        r'\bmongodb\b': 'MongoDB',
        r'\bmongo\b(?!db)': 'MongoDB',
        r'\bpostgresql\b': 'PostgreSQL',
        r'\bpostgres\b': 'PostgreSQL',
        r'\bredis\b': 'Redis',
        r'\bsqlite\b': 'SQLite',
        r'\boracle\b': 'Oracle',
        r'\bsql\s*server\b': 'SQL Server',
        
        # Mobile & Frameworks
        r'\bflutter\b': 'Flutter',
        r'\bfirebase\b': 'Firebase',
        r'\bandroid\b': 'Android',
        r'\bios\b': 'iOS',
        r'\breact\s*native\b': 'React Native',
        r'\bdjango\b': 'Django',
        r'\bflask\b': 'Flask',
        r'\bfastapi\b': 'FastAPI',
        r'\bspring\b': 'Spring',
        r'\blaravel\b': 'Laravel',
        
        # Cloud & DevOps - be more specific
        r'\baws\b': 'AWS',
        r'\bazure\b': 'Azure',
        r'\bgoogle\s*cloud\b': 'Google Cloud',
        r'\bgcp\b': 'Google Cloud Platform',
        r'\bdocker\b': 'Docker',
        r'\bkubernetes\b': 'Kubernetes',
        r'\bk8s\b': 'Kubernetes',
        r'\bgit\b(?!hub|lab)': 'Git',  # Git but not GitHub/GitLab
        r'\bgithub\b': 'GitHub',
        r'\bgitlab\b': 'GitLab',
        
        # Concepts and Skills
        r'\boop\b': 'OOP',
        r'\bobject\s*oriented\b': 'OOP',
        r'\bdata\s*structures\b': 'Data Structures',
        r'\balgorithms\b': 'Algorithms',
        r'\bdsa\b': 'Data Structures and Algorithms',
        r'\bdbms\b': 'DBMS',
        r'\bdatabase\s*design\b': 'Database Design',
        r'\bproblem\s*solving\b': 'Problem Solving',
        r'\bsystem\s*design\b': 'System Design',
        r'\bsoftware\s*architecture\b': 'Software Architecture',
        r'\bdesign\s*patterns\b': 'Design Patterns',
        r'\bmachine\s*learning\b': 'Machine Learning',
        r'\bml\b(?!\s*project)': 'Machine Learning',  # ML but not "ML PROJECT"
        r'\bdeep\s*learning\b': 'Deep Learning',
        r'\bartificial\s*intelligence\b': 'Artificial Intelligence',
        r'\bai\b(?!\s*powered)': 'AI',  # AI but not "AI powered"
        r'\bdata\s*analysis\b': 'Data Analysis',
        r'\bdata\s*science\b': 'Data Science',
        
        # Testing and Development Practices
        r'\bunit\s*testing\b': 'Unit Testing',
        r'\btdd\b': 'Test Driven Development',
        r'\btesting\b': 'Testing',
        r'\bdebugging\b': 'Debugging',
        r'\bagile\b': 'Agile',
        r'\bscrum\b': 'Scrum',
        r'\bdevops\b': 'DevOps',
        r'\bci/cd\b': 'CI/CD',
        
        # Operating Systems
        r'\blinux\b': 'Linux',
        r'\bunix\b': 'Unix',
        r'\bwindows\b': 'Windows',
        r'\bmacos\b': 'macOS',
        r'\bubuntu\b': 'Ubuntu',
        
        # Tools and IDEs
        r'\bvscode\b': 'VS Code',
        r'\bvisual\s*studio\b': 'Visual Studio',
        r'\bintellij\b': 'IntelliJ IDEA',
        r'\beclipse\b': 'Eclipse',
        
        # Data Science Libraries
        r'\btensorflow\b': 'TensorFlow',
        r'\bpytorch\b': 'PyTorch',
        r'\bpandas\b': 'Pandas',
        r'\bnumpy\b': 'NumPy',
        r'\bscikit-learn\b': 'Scikit-learn',
        r'\bmatplotlib\b': 'Matplotlib',
        r'\bjupyter\b': 'Jupyter',
        
        # Networking (be more specific)
        r'\btcp/ip\b': 'TCP/IP',
        r'\bhttp\b(?!s)': 'HTTP',
        r'\bhttps\b': 'HTTPS',
        r'\bssl/tls\b': 'SSL/TLS',
        r'\bssl\s+tls\b': 'SSL/TLS',
        
        # Other Technologies
        r'\bgraphql\b': 'GraphQL',
        r'\brest\s*api\b': 'REST API',
        r'\bapi\s*development\b': 'API Development',
        r'\bmicroservices\b': 'Microservices',
        r'\bjson\b': 'JSON',
        r'\bxml\b': 'XML',
    }
    
    found_skills = set()
    
    # Use regex patterns for more precise matching
    for pattern, skill_name in skill_patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            found_skills.add(skill_name)
    
    # Convert to list and limit to reasonable number
    skills_list = list(found_skills)
    
    # Remove duplicates and sort
    skills_list = sorted(list(set(skills_list)))
    
    # If no skills found, return empty list instead of generic skills
    if not skills_list:
        return []
    
    return skills_list[:30]  # Allow up to 30 skills for more comprehensive extraction

# Demo data
SAMPLE_SKILLS = [
    "Python", "JavaScript", "React", "FastAPI", "MySQL", "Docker", 
    "Git", "HTML", "CSS", "Machine Learning", "Data Analysis", "SQL",
    "Node.js", "AWS", "Linux", "API Development", "Database Design"
]

SAMPLE_COURSES = [
    {
        "title": "Advanced Python Programming",
        "provider": "Coursera",
        "level": "Intermediate",
        "duration": "6 weeks",
        "price": "Free",
        "rating": 4.8,
        "url": "https://coursera.org/python-advanced"
    },
    {
        "title": "React.js Complete Guide",
        "provider": "Udemy", 
        "level": "Beginner",
        "duration": "40 hours",
        "price": "$89.99",
        "rating": 4.7,
        "url": "https://udemy.com/react-complete"
    },
    {
        "title": "Machine Learning Fundamentals",
        "provider": "edX",
        "level": "Intermediate",
        "duration": "8 weeks", 
        "price": "$199",
        "rating": 4.9,
        "url": "https://edx.org/ml-fundamentals"
    }
]

# Routes
@app.get("/")
async def root():
    return {"message": "Skill Gap Analyzer API - Demo Version", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}

# Authentication routes
@app.post("/api/v1/auth/register")
async def register(user: UserCreate):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = len(users_db) + 1
    users_db[user.email] = {
        "id": user_id,
        "email": user.email,
        "password": user.password,  # In real app, hash this!
        "full_name": user.full_name,
        "created_at": datetime.now()
    }
    
    return {"message": "User registered successfully", "user_id": user_id}

@app.post("/api/v1/auth/login")
async def login(user: UserLogin):
    if user.email not in users_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    stored_user = users_db[user.email]
    if stored_user["password"] != user.password:  # In real app, verify hashed password
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # In real app, return JWT token
    return {
        "access_token": f"demo_token_{stored_user['id']}",
        "token_type": "bearer",
        "user": {
            "id": stored_user["id"],
            "email": stored_user["email"],
            "full_name": stored_user["full_name"]
        }
    }

@app.get("/api/v1/auth/profile")
async def get_profile():
    # Demo user profile
    return {
        "id": 1,
        "email": "demo@example.com",
        "full_name": "Demo User",
        "created_at": datetime.now()
    }

# Resume routes
@app.post("/api/v1/resumes/upload")
async def upload_resume(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Simulate file processing
    resume_id = len(resumes_db) + 1
    
    # Read file content for basic skill extraction
    content = await file.read()
    content_text = ""
    
    try:
        # Try to decode as text
        content_text = content.decode('utf-8').lower()
    except:
        try:
            # Try other encoding
            content_text = content.decode('latin-1').lower()
        except:
            content_text = str(content).lower()
    
    # Basic skill extraction based on content
    extracted_skills = extract_skills_from_text(content_text)
    
    resume_info = {
        "id": resume_id,
        "filename": file.filename,
        "status": "completed",
        "upload_date": datetime.now(),
        "extracted_skills": extracted_skills,
        "content_type": file.content_type,
        "file_content": content_text  # Store for reprocessing
    }
    
    resumes_db[resume_id] = resume_info
    
    return {"message": "Resume uploaded successfully", "resume": resume_info}

@app.get("/api/v1/resumes")
async def list_resumes():
    return {"resumes": list(resumes_db.values())}

@app.get("/api/v1/resumes/{resume_id}")
async def get_resume(resume_id: int):
    if resume_id not in resumes_db:
        raise HTTPException(status_code=404, detail="Resume not found")
    return resumes_db[resume_id]

@app.delete("/api/v1/resumes/{resume_id}")
async def delete_resume(resume_id: int):
    if resume_id not in resumes_db:
        raise HTTPException(status_code=404, detail="Resume not found")
    
    del resumes_db[resume_id]
    return {"message": "Resume deleted successfully"}

@app.post("/api/v1/resumes/{resume_id}/reprocess")
async def reprocess_resume(resume_id: int):
    if resume_id not in resumes_db:
        raise HTTPException(status_code=404, detail="Resume not found")
    
    # Update status to processing
    resumes_db[resume_id]["status"] = "processing"
    
    # Re-extract skills from stored content
    stored_content = resumes_db[resume_id].get("file_content", "")
    if stored_content:
        new_skills = extract_skills_from_text(stored_content)
        resumes_db[resume_id]["extracted_skills"] = new_skills
    
    # Mark as completed
    resumes_db[resume_id]["status"] = "completed"
    
    return {"message": "Resume reprocessing completed", "resume": resumes_db[resume_id]}

# Analysis routes
@app.post("/api/v1/analysis/analyze")
async def perform_analysis(analysis_request: AnalysisRequest):
    if analysis_request.resume_id not in resumes_db:
        raise HTTPException(status_code=404, detail="Resume not found")
    
    resume = resumes_db[analysis_request.resume_id]
    
    # Simulate skill gap analysis
    import random
    
    user_skills = resume["extracted_skills"]
    
    # Generate random job requirements based on job title
    job_skills = random.sample(SAMPLE_SKILLS, k=random.randint(8, 12))
    
    # Find strong skills (intersection)
    strong_skills = list(set(user_skills) & set(job_skills))
    
    # Find missing skills (job requirements not in user skills)
    missing_skills = list(set(job_skills) - set(user_skills))
    
    # Calculate overall score
    if len(job_skills) > 0:
        overall_score = (len(strong_skills) / len(job_skills)) * 100
    else:
        overall_score = 0.0
    
    # Generate course recommendations for missing skills
    recommended_courses = random.sample(SAMPLE_COURSES, k=min(3, len(SAMPLE_COURSES)))
    
    analysis_id = len(analyses_db) + 1
    analysis_result = {
        "id": analysis_id,
        "resume_id": analysis_request.resume_id,
        "job_title": analysis_request.job_title,
        "overall_score": round(overall_score, 1),
        "strong_skills": strong_skills,
        "missing_skills": missing_skills,
        "recommended_courses": recommended_courses,
        "analysis_date": datetime.now()
    }
    
    analyses_db[analysis_id] = analysis_result
    
    return analysis_result

@app.get("/api/v1/analysis/history")
async def get_analysis_history():
    return {"analyses": list(analyses_db.values())}

@app.get("/api/v1/analysis/{analysis_id}")
async def get_analysis(analysis_id: int):
    if analysis_id not in analyses_db:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analyses_db[analysis_id]

# Skills and Jobs routes
@app.get("/api/v1/skills-jobs/skills")
async def list_skills():
    return {"skills": SAMPLE_SKILLS}

@app.get("/api/v1/skills-jobs/jobs")
async def list_jobs():
    job_titles = [
        "Software Engineer", "Data Scientist", "Web Developer", "DevOps Engineer",
        "Machine Learning Engineer", "Frontend Developer", "Backend Developer",
        "Full Stack Developer", "Data Analyst", "Product Manager"
    ]
    jobs = []
    for i, title in enumerate(job_titles, 1):
        jobs.append({
            "id": i,
            "title": title,
            "category": "Technology" if "Engineer" in title or "Developer" in title else "Business"
        })
    return {"jobs": jobs}

# Course recommendation routes
@app.get("/api/v1/courses/recommendations")
async def get_course_recommendations(skills: Optional[str] = None):
    # Return sample courses
    return {"courses": SAMPLE_COURSES}

@app.get("/api/v1/courses/search")
async def search_courses(
    query: Optional[str] = None,
    provider: Optional[str] = None,
    level: Optional[str] = None
):
    courses = SAMPLE_COURSES.copy()
    
    # Simple filtering
    if provider:
        courses = [c for c in courses if c["provider"].lower() == provider.lower()]
    if level:
        courses = [c for c in courses if c["level"].lower() == level.lower()]
    if query:
        courses = [c for c in courses if query.lower() in c["title"].lower()]
    
    return {"courses": courses}

# Dashboard routes
@app.get("/api/v1/dashboard/stats")
async def get_dashboard_stats():
    return {
        "total_resumes": len(resumes_db),
        "total_analyses": len(analyses_db),
        "avg_skill_match": 75.5,
        "trending_skills": ["Python", "React", "Machine Learning", "Docker", "AWS"]
    }

if __name__ == "__main__":
    uvicorn.run(
        "demo_main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
