"""
Skill gap analysis API endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks
import logging
from datetime import datetime
import asyncio
import time
from typing import List, Dict, Any

from ..models.schemas import (
    SkillGapAnalysisRequest, SkillGapAnalysisResponse, SkillGapAnalysisResult,
    VisualizationData, SkillMatch, LearningPathItem, Recommendation,
    AnalysisHistoryResponse, AnalysisHistoryItem, ErrorResponse
)
from ..utils.auth import get_current_user
from ..utils.database import (
    save_skill_analysis, get_user_analyses, get_job_required_skills,
    save_course_recommendations, get_course_recommendations, db_manager
)
from ..services.skill_analyzer import SkillGapAnalyzer, load_skills_from_resume_text
from ..services.spacy_trainer import SkillExtractor
from config import Config

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analysis", tags=["Skill Gap Analysis"])

# Initialize analyzers (will be loaded when first needed)
skill_analyzer = None
skill_extractor = None

def get_skill_analyzer():
    """Get or initialize skill analyzer"""
    global skill_analyzer
    if skill_analyzer is None:
        try:
            skill_embeddings_path = Config.PROCESSED_DATA_PATH + "skill_embeddings.json"
            job_mapping_path = Config.PROCESSED_DATA_PATH + "job_skill_mapping.json"
            skill_analyzer = SkillGapAnalyzer(
                skill_embeddings_path=skill_embeddings_path,
                job_skill_mapping_path=job_mapping_path,
                similarity_threshold=Config.SKILL_SIMILARITY_THRESHOLD
            )
            logger.info("Skill analyzer initialized successfully")
        except Exception as e:
            logger.error(f"Could not initialize skill analyzer: {e}")
            skill_analyzer = None
    return skill_analyzer

def get_skill_extractor():
    """Get or initialize skill extractor"""
    global skill_extractor
    if skill_extractor is None:
        try:
            skill_extractor = SkillExtractor(Config.SPACY_MODEL_PATH)
            logger.info("Skill extractor initialized successfully")
        except Exception as e:
            logger.warning(f"Could not load spaCy model: {e}")
            skill_extractor = None
    return skill_extractor

async def perform_skill_gap_analysis(
    user_id: str, 
    resume_id: str, 
    target_job_id: str
) -> Dict[str, Any]:
    """
    Perform comprehensive skill gap analysis
    
    Returns analysis results and visualizations
    """
    try:
        start_time = time.time()
        
        # Get resume data
        resume_query = """
            SELECT r.*, GROUP_CONCAT(s.name SEPARATOR ', ') as extracted_skills
            FROM resumes r
            LEFT JOIN resume_skills rs ON r.id = rs.resume_id
            LEFT JOIN skills s ON rs.skill_id = s.id
            WHERE r.id = %s AND r.user_id = %s
            GROUP BY r.id
        """
        resume_data = db_manager.execute_query(resume_query, (resume_id, user_id), fetch='one')
        
        if not resume_data:
            raise ValueError("Resume not found")
        
        # Get job data
        job_query = "SELECT * FROM job_professions WHERE id = %s"
        job_data = db_manager.execute_query(job_query, (target_job_id,), fetch='one')
        
        if not job_data:
            raise ValueError("Job not found")
        
        # Extract skills from resume text
        analyzer = get_skill_analyzer()
        extractor = get_skill_extractor()
        
        resume_skills = []
        
        if resume_data.get('extracted_skills'):
            # Use already extracted skills from database
            resume_skills = [skill.strip() for skill in resume_data['extracted_skills'].split(',') if skill.strip()]
        elif extractor:
            # Extract skills using spaCy model
            resume_skills = load_skills_from_resume_text(resume_data['raw_text'], extractor)
        else:
            # Fallback: simple keyword matching
            all_skills_query = "SELECT name FROM skills"
            all_skills = db_manager.execute_query(all_skills_query, fetch='all')
            resume_text_lower = resume_data['raw_text'].lower()
            
            for skill in all_skills or []:
                if skill['name'].lower() in resume_text_lower:
                    resume_skills.append(skill['name'])
        
        if analyzer:
            # Use advanced skill gap analyzer
            analysis_result = analyzer.analyze_skill_gap(resume_skills, job_data['name'])
            visualizations = analyzer.create_skill_gap_visualization(analysis_result)
        else:
            # Fallback: basic analysis
            analysis_result = perform_basic_analysis(resume_skills, target_job_id, job_data['name'])
            visualizations = create_basic_visualizations(analysis_result)
        
        # Save analysis to database
        analysis_id = save_skill_analysis(
            user_id=user_id,
            resume_id=resume_id,
            target_job_id=target_job_id,
            analysis_results=analysis_result,
            visualizations=visualizations
        )
        
        analysis_result['analysis_id'] = analysis_id
        processing_time = time.time() - start_time
        
        logger.info(f"Analysis completed for user {user_id} in {processing_time:.2f}s")
        
        return {
            'analysis': analysis_result,
            'visualizations': visualizations,
            'processing_time': processing_time
        }
        
    except Exception as e:
        logger.error(f"Error performing skill gap analysis: {e}")
        raise

def perform_basic_analysis(resume_skills: List[str], target_job_id: str, job_name: str) -> Dict[str, Any]:
    """
    Perform basic skill gap analysis when advanced analyzer is not available
    """
    # Get job required skills
    required_skills_data = get_job_required_skills(target_job_id)
    required_skills = [skill['name'] for skill in required_skills_data or []]
    
    # Calculate matches
    present_skills = []
    missing_skills = []
    
    for required_skill in required_skills:
        if any(required_skill.lower() in resume_skill.lower() for resume_skill in resume_skills):
            present_skills.append(required_skill)
        else:
            missing_skills.append(required_skill)
    
    proficiency_score = (len(present_skills) / max(len(required_skills), 1)) * 100
    
    # Categorize missing skills
    critical_missing = []
    important_missing = []
    nice_to_have_missing = []
    
    for skill_data in required_skills_data or []:
        skill_name = skill_data['name']
        if skill_name in missing_skills:
            importance = skill_data.get('importance_level', 'Important')
            if importance == 'Critical':
                critical_missing.append(skill_name)
            elif importance == 'Important':
                important_missing.append(skill_name)
            else:
                nice_to_have_missing.append(skill_name)
    
    # Generate recommendations
    recommendations = []
    for skill in critical_missing:
        recommendations.append({
            'skill': skill,
            'priority': 'Critical',
            'reason': 'Essential skill for this role'
        })
    
    for skill in important_missing[:5]:  # Limit to top 5
        recommendations.append({
            'skill': skill,
            'priority': 'Important',
            'reason': 'Important skill for career growth'
        })
    
    return {
        'target_job': job_name,
        'proficiency_score': proficiency_score,
        'total_required_skills': len(required_skills),
        'skills_present': len(present_skills),
        'present_skills': present_skills,
        'missing_skills': missing_skills,
        'critical_missing': critical_missing,
        'important_missing': important_missing,
        'nice_to_have_missing': nice_to_have_missing,
        'recommendations': recommendations,
        'learning_path': create_basic_learning_path(critical_missing + important_missing[:3])
    }

def create_basic_learning_path(skills: List[str]) -> List[Dict[str, Any]]:
    """Create basic learning path for missing skills"""
    learning_path = []
    
    # Basic skill categorization and time estimates
    for i, skill in enumerate(skills):
        category = categorize_skill_basic(skill)
        weeks = estimate_learning_time_basic(skill)
        
        learning_path.append({
            'skill': skill,
            'category': category,
            'estimated_weeks': weeks,
            'prerequisites': []
        })
    
    return learning_path

def categorize_skill_basic(skill: str) -> str:
    """Basic skill categorization"""
    skill_lower = skill.lower()
    
    if any(keyword in skill_lower for keyword in ['python', 'java', 'javascript', 'programming']):
        return 'Programming Languages'
    elif any(keyword in skill_lower for keyword in ['machine learning', 'ai', 'data science']):
        return 'Data Science'
    elif any(keyword in skill_lower for keyword in ['sql', 'database', 'mysql']):
        return 'Database'
    elif any(keyword in skill_lower for keyword in ['cloud', 'aws', 'azure']):
        return 'Cloud Computing'
    else:
        return 'Other'

def estimate_learning_time_basic(skill: str) -> int:
    """Basic learning time estimation"""
    skill_lower = skill.lower()
    
    if any(keyword in skill_lower for keyword in ['python', 'java', 'programming']):
        return 8
    elif any(keyword in skill_lower for keyword in ['machine learning', 'ai']):
        return 12
    elif any(keyword in skill_lower for keyword in ['sql', 'database']):
        return 4
    else:
        return 6

def create_basic_visualizations(analysis_result: Dict[str, Any]) -> Dict[str, str]:
    """Create basic visualizations when advanced analyzer is not available"""
    try:
        import plotly.graph_objects as go
        import json
        
        # Proficiency gauge
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=analysis_result["proficiency_score"],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Skill Proficiency Score"},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "green"}
                ]
            }
        ))
        
        # Skill gap bar chart
        categories = ["Present Skills", "Critical Missing", "Important Missing", "Nice-to-have Missing"]
        values = [
            len(analysis_result["present_skills"]),
            len(analysis_result["critical_missing"]),
            len(analysis_result["important_missing"]),
            len(analysis_result["nice_to_have_missing"])
        ]
        colors = ["green", "red", "orange", "lightblue"]
        
        fig_bar = go.Figure(data=[
            go.Bar(x=categories, y=values, marker_color=colors)
        ])
        fig_bar.update_layout(
            title="Skill Gap Analysis",
            xaxis_title="Skill Categories",
            yaxis_title="Number of Skills"
        )
        
        return {
            'proficiency_gauge': fig_gauge.to_json(),
            'skill_gap_bar': fig_bar.to_json()
        }
        
    except Exception as e:
        logger.error(f"Error creating visualizations: {e}")
        return {
            'proficiency_gauge': '{}',
            'skill_gap_bar': '{}'
        }

@router.post("/analyze",
             response_model=SkillGapAnalysisResponse,
             status_code=status.HTTP_201_CREATED,
             responses={
                 400: {"model": ErrorResponse, "description": "Invalid request"},
                 404: {"model": ErrorResponse, "description": "Resume or job not found"}
             })
async def analyze_skill_gap(
    analysis_request: SkillGapAnalysisRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Perform skill gap analysis for a resume against a target job
    
    - **resume_id**: ID of the processed resume
    - **target_job_id**: ID of the target job profession
    
    Returns comprehensive analysis with visualizations
    """
    try:
        # Verify resume belongs to user
        resume_check_query = "SELECT id FROM resumes WHERE id = %s AND user_id = %s AND processed = TRUE"
        resume_exists = db_manager.execute_query(
            resume_check_query, 
            (analysis_request.resume_id, current_user["id"]), 
            fetch='one'
        )
        
        if not resume_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found or not processed yet"
            )
        
        # Verify job exists
        job_check_query = "SELECT id FROM job_professions WHERE id = %s"
        job_exists = db_manager.execute_query(job_check_query, (analysis_request.target_job_id,), fetch='one')
        
        if not job_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job profession not found"
            )
        
        # Perform analysis
        result = await perform_skill_gap_analysis(
            user_id=current_user["id"],
            resume_id=analysis_request.resume_id,
            target_job_id=analysis_request.target_job_id
        )
        
        # Convert to response format
        analysis_result = SkillGapAnalysisResult(
            analysis_id=result['analysis']['analysis_id'],
            target_job=result['analysis']['target_job'],
            proficiency_score=result['analysis']['proficiency_score'],
            total_required_skills=result['analysis']['total_required_skills'],
            skills_present=result['analysis']['skills_present'],
            present_skills=result['analysis']['present_skills'],
            missing_skills=result['analysis']['missing_skills'],
            critical_missing=result['analysis']['critical_missing'],
            important_missing=result['analysis']['important_missing'],
            nice_to_have_missing=result['analysis']['nice_to_have_missing'],
            recommendations=[
                Recommendation(
                    skill=rec['skill'],
                    priority=rec['priority'],
                    reason=rec['reason']
                ) for rec in result['analysis'].get('recommendations', [])
            ],
            learning_path=[
                LearningPathItem(
                    skill=item['skill'],
                    category=item['category'],
                    estimated_weeks=item['estimated_weeks'],
                    prerequisites=item.get('prerequisites', [])
                ) for item in result['analysis'].get('learning_path', [])
            ]
        )
        
        visualizations = VisualizationData(
            proficiency_gauge=result['visualizations']['proficiency_gauge'],
            skill_gap_bar=result['visualizations']['skill_gap_bar'],
            category_pie=result['visualizations'].get('category_pie'),
            learning_timeline=result['visualizations'].get('learning_timeline')
        )
        
        logger.info(f"Skill gap analysis completed for user {current_user['id']}")
        
        return SkillGapAnalysisResponse(
            analysis=analysis_result,
            visualizations=visualizations,
            created_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in skill gap analysis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error performing skill gap analysis"
        )

@router.get("/history",
            response_model=AnalysisHistoryResponse,
            responses={
                200: {"description": "User's analysis history"}
            })
async def get_analysis_history(
    page: int = Query(1, description="Page number (1-based)"),
    page_size: int = Query(10, description="Number of items per page"),
    current_user: dict = Depends(get_current_user)
):
    """
    Get user's skill gap analysis history
    
    - **page**: Page number (1-based, default: 1)
    - **page_size**: Items per page (default: 10, max: 50)
    """
    try:
        # Validate pagination parameters
        page = max(1, page)
        page_size = min(max(1, page_size), 50)
        offset = (page - 1) * page_size
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM skill_analyses WHERE user_id = %s"
        total_count = db_manager.execute_query(count_query, (current_user["id"],), fetch='one')
        total = total_count['total'] if total_count else 0
        
        # Get analyses
        analyses_query = """
            SELECT 
                sa.id,
                sa.proficiency_score,
                sa.total_required_skills,
                sa.skills_present,
                sa.created_at,
                jp.name as target_job_name,
                jp.category as job_category,
                r.filename as resume_filename
            FROM skill_analyses sa
            JOIN job_professions jp ON sa.target_job_id = jp.id
            JOIN resumes r ON sa.resume_id = r.id
            WHERE sa.user_id = %s
            ORDER BY sa.created_at DESC
            LIMIT %s OFFSET %s
        """
        
        analyses_data = db_manager.execute_query(
            analyses_query, 
            (current_user["id"], page_size, offset), 
            fetch='all'
        )
        
        # Convert to response format
        analyses = []
        for analysis in analyses_data or []:
            analyses.append(AnalysisHistoryItem(
                id=analysis['id'],
                target_job_name=analysis['target_job_name'],
                job_category=analysis['job_category'],
                proficiency_score=float(analysis['proficiency_score']),
                total_required_skills=int(analysis['total_required_skills']),
                skills_present=int(analysis['skills_present']),
                created_at=analysis['created_at'],
                resume_filename=analysis['resume_filename']
            ))
        
        return AnalysisHistoryResponse(
            analyses=analyses,
            total_count=total,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error(f"Error getting analysis history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving analysis history"
        )

@router.get("/{analysis_id}",
            response_model=SkillGapAnalysisResponse,
            responses={
                404: {"model": ErrorResponse, "description": "Analysis not found"}
            })
async def get_analysis_details(
    analysis_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed results of a specific skill gap analysis
    
    - **analysis_id**: ID of the analysis to retrieve
    """
    try:
        # Get analysis data
        analysis_query = """
            SELECT sa.*, jp.name as job_name
            FROM skill_analyses sa
            JOIN job_professions jp ON sa.target_job_id = jp.id
            WHERE sa.id = %s AND sa.user_id = %s
        """
        analysis_data = db_manager.execute_query(
            analysis_query, 
            (analysis_id, current_user["id"]), 
            fetch='one'
        )
        
        if not analysis_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Analysis not found"
            )
        
        # Parse stored JSON results
        import json
        analysis_results = json.loads(analysis_data['analysis_results'])
        visualizations_data = json.loads(analysis_data['visualizations'])
        
        # Convert to response format
        analysis_result = SkillGapAnalysisResult(
            analysis_id=analysis_id,
            target_job=analysis_results['target_job'],
            proficiency_score=analysis_results['proficiency_score'],
            total_required_skills=analysis_results['total_required_skills'],
            skills_present=analysis_results['skills_present'],
            present_skills=analysis_results.get('present_skills', []),
            missing_skills=analysis_results.get('missing_skills', []),
            critical_missing=analysis_results.get('critical_missing', []),
            important_missing=analysis_results.get('important_missing', []),
            nice_to_have_missing=analysis_results.get('nice_to_have_missing', []),
            recommendations=[
                Recommendation(**rec) for rec in analysis_results.get('recommendations', [])
            ],
            learning_path=[
                LearningPathItem(**item) for item in analysis_results.get('learning_path', [])
            ]
        )
        
        visualizations = VisualizationData(
            proficiency_gauge=visualizations_data.get('proficiency_gauge', '{}'),
            skill_gap_bar=visualizations_data.get('skill_gap_bar', '{}'),
            category_pie=visualizations_data.get('category_pie'),
            learning_timeline=visualizations_data.get('learning_timeline')
        )
        
        return SkillGapAnalysisResponse(
            analysis=analysis_result,
            visualizations=visualizations,
            created_at=analysis_data['created_at']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting analysis details: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving analysis details"
        )
