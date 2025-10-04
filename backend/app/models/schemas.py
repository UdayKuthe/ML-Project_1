"""
Pydantic models for API request and response validation
"""

from pydantic import BaseModel, EmailStr, validator
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum

# Enums
class ImportanceLevel(str, Enum):
    CRITICAL = "Critical"
    IMPORTANT = "Important" 
    NICE_TO_HAVE = "Nice-to-have"

class DifficultyLevel(str, Enum):
    BEGINNER = "Beginner"
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"

class MatchType(str, Enum):
    EXACT = "exact"
    SEMANTIC = "semantic"
    FUZZY = "fuzzy"

# Authentication Models
class UserRegistrationRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('full_name')
    def name_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Full name cannot be empty')
        return v.strip()

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

# Skills and Jobs Models
class SkillResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    is_hot_technology: bool = False
    is_in_demand: bool = False

class JobProfessionResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None

class JobSkillRequirement(BaseModel):
    id: str
    skill: SkillResponse
    importance_level: ImportanceLevel
    task_description: Optional[str] = None

class JobWithSkillsResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    required_skills: List[JobSkillRequirement] = []
    total_skills: int = 0

# Resume Models
class ResumeUploadResponse(BaseModel):
    resume_id: str
    filename: str
    file_size: int
    mime_type: str
    text_extracted: bool
    processing_started: bool
    message: str

class ExtractedSkill(BaseModel):
    text: str
    skill_name: str
    confidence_score: float
    match_type: MatchType
    position_start: Optional[int] = None
    position_end: Optional[int] = None

class ResumeProcessingResult(BaseModel):
    resume_id: str
    processed: bool
    skills_found: int
    extracted_skills: List[ExtractedSkill] = []
    processing_time_seconds: float

# Analysis Models
class SkillGapAnalysisRequest(BaseModel):
    resume_id: str
    target_job_id: str

class SkillMatch(BaseModel):
    original_skill: str
    matched_skill: str
    confidence: float
    match_type: str

class LearningPathItem(BaseModel):
    skill: str
    category: str
    estimated_weeks: int
    prerequisites: List[str] = []

class Recommendation(BaseModel):
    skill: str
    priority: str
    reason: str

class SkillGapAnalysisResult(BaseModel):
    analysis_id: str
    target_job: str
    proficiency_score: float
    total_required_skills: int
    skills_present: int
    matched_skills: List[SkillMatch] = []
    present_skills: List[str] = []
    missing_skills: List[str] = []
    critical_missing: List[str] = []
    important_missing: List[str] = []
    nice_to_have_missing: List[str] = []
    recommendations: List[Recommendation] = []
    learning_path: List[LearningPathItem] = []
    skill_categories: Dict[str, List[str]] = {}

class VisualizationData(BaseModel):
    proficiency_gauge: str  # JSON string
    skill_gap_bar: str      # JSON string
    category_pie: Optional[str] = None        # JSON string
    learning_timeline: Optional[str] = None   # JSON string

class SkillGapAnalysisResponse(BaseModel):
    analysis: SkillGapAnalysisResult
    visualizations: VisualizationData
    created_at: datetime

# Course Recommendation Models
class CourseRecommendation(BaseModel):
    id: str
    skill_name: str
    course_title: str
    course_provider: str
    course_url: Optional[str] = None
    course_description: Optional[str] = None
    estimated_duration: Optional[str] = None
    difficulty_level: Optional[DifficultyLevel] = None
    rating: Optional[float] = None
    price: Optional[str] = None
    recommendation_score: float
    priority: ImportanceLevel

class CourseRecommendationsResponse(BaseModel):
    analysis_id: str
    recommendations: List[CourseRecommendation] = []
    total_recommendations: int
    generated_at: datetime

# Dashboard Models
class UserStats(BaseModel):
    total_resumes: int
    total_analyses: int
    recent_analyses: int
    avg_proficiency_score: Optional[float] = None
    best_proficiency_score: Optional[float] = None

class AnalysisSummary(BaseModel):
    id: str
    target_job_name: str
    proficiency_score: float
    created_at: datetime
    resume_filename: str

class DashboardResponse(BaseModel):
    user_stats: UserStats
    recent_analyses: List[AnalysisSummary] = []
    trending_skills: List[SkillResponse] = []

# Search Models
class SearchRequest(BaseModel):
    query: str
    limit: int = 20
    
    @validator('query')
    def query_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Search query cannot be empty')
        return v.strip()

class JobSearchResponse(BaseModel):
    jobs: List[JobProfessionResponse]
    total_found: int

class SkillSearchResponse(BaseModel):
    skills: List[SkillResponse]
    total_found: int

# Time Series Models
class SkillTrendData(BaseModel):
    date_period: str  # YYYY-MM format
    demand_score: float
    job_postings_count: int
    salary_trend: Optional[float] = None
    growth_rate: Optional[float] = None

class SkillTrendResponse(BaseModel):
    skill_id: str
    skill_name: str
    trend_data: List[SkillTrendData]
    latest_score: float
    avg_growth_rate: float

# Error Models
class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    timestamp: datetime = datetime.utcnow()

class ValidationErrorResponse(BaseModel):
    error: str
    validation_errors: List[Dict[str, Any]]
    timestamp: datetime = datetime.utcnow()

# Success Response Models
class SuccessResponse(BaseModel):
    message: str
    success: bool = True
    timestamp: datetime = datetime.utcnow()

class MessageResponse(BaseModel):
    message: str
    details: Optional[Dict[str, Any]] = None

# File Upload Models
class FileValidationResponse(BaseModel):
    valid: bool
    error: Optional[str] = None
    file_info: Optional[Dict[str, Any]] = None

# Analysis History Models
class AnalysisHistoryItem(BaseModel):
    id: str
    target_job_name: str
    job_category: str
    proficiency_score: float
    total_required_skills: int
    skills_present: int
    created_at: datetime
    resume_filename: str

class AnalysisHistoryResponse(BaseModel):
    analyses: List[AnalysisHistoryItem]
    total_count: int
    page: int
    page_size: int

# Configuration Models
class ConfigResponse(BaseModel):
    max_file_size_mb: float
    allowed_file_types: List[str]
    supported_job_categories: List[str]
    skill_categories: List[str]

# Health Check Models
class HealthCheckResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    database_connected: bool
    services_status: Dict[str, str]
