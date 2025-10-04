"""
Skills and Jobs API endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends, Query
import logging
from typing import List, Optional

from ..models.schemas import (
    SkillResponse, JobProfessionResponse, JobWithSkillsResponse, JobSkillRequirement,
    SearchRequest, JobSearchResponse, SkillSearchResponse, ErrorResponse
)
from ..utils.auth import get_current_user
from ..utils.database import (
    get_all_skills, get_all_job_professions, get_job_required_skills,
    search_jobs, search_skills, get_trending_skills
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/skills-jobs", tags=["Skills & Jobs"])

@router.get("/skills",
            response_model=List[SkillResponse],
            responses={
                200: {"description": "List of all skills"}
            })
async def get_skills(
    category: Optional[str] = Query(None, description="Filter by skill category"),
    hot_tech_only: Optional[bool] = Query(False, description="Show only hot technologies"),
    in_demand_only: Optional[bool] = Query(False, description="Show only in-demand skills"),
    limit: Optional[int] = Query(100, description="Maximum number of skills to return")
):
    """
    Get all available skills with optional filtering
    
    - **category**: Filter by skill category (Programming Languages, Machine Learning/AI, etc.)
    - **hot_tech_only**: Return only skills marked as hot technologies
    - **in_demand_only**: Return only skills marked as in-demand
    - **limit**: Maximum number of skills to return (default: 100)
    """
    try:
        from ..utils.database import db_manager
        
        # Build query with filters
        query = """
            SELECT id, name, description, category, is_hot_technology, is_in_demand
            FROM skills
            WHERE 1=1
        """
        params = []
        
        if category:
            query += " AND category = %s"
            params.append(category)
        
        if hot_tech_only:
            query += " AND is_hot_technology = TRUE"
        
        if in_demand_only:
            query += " AND is_in_demand = TRUE"
        
        query += " ORDER BY name LIMIT %s"
        params.append(limit)
        
        skills_data = db_manager.execute_query(query, tuple(params), fetch='all')
        
        # Convert to response format
        skills = []
        for skill in skills_data or []:
            skills.append(SkillResponse(
                id=skill['id'],
                name=skill['name'],
                description=skill.get('description'),
                category=skill.get('category'),
                is_hot_technology=bool(skill['is_hot_technology']),
                is_in_demand=bool(skill['is_in_demand'])
            ))
        
        return skills
        
    except Exception as e:
        logger.error(f"Error getting skills: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving skills"
        )

@router.get("/skills/categories",
            response_model=List[str],
            responses={
                200: {"description": "List of skill categories"}
            })
async def get_skill_categories():
    """
    Get all available skill categories
    
    Returns unique list of skill categories
    """
    try:
        from ..utils.database import db_manager
        
        query = "SELECT DISTINCT category FROM skills WHERE category IS NOT NULL ORDER BY category"
        categories_data = db_manager.execute_query(query, fetch='all')
        
        categories = [cat['category'] for cat in categories_data or []]
        return categories
        
    except Exception as e:
        logger.error(f"Error getting skill categories: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving skill categories"
        )

@router.get("/skills/trending",
            response_model=List[SkillResponse],
            responses={
                200: {"description": "List of trending skills"}
            })
async def get_trending_skills_endpoint(
    limit: Optional[int] = Query(20, description="Maximum number of trending skills to return")
):
    """
    Get trending skills based on demand and growth rates
    
    - **limit**: Maximum number of skills to return (default: 20)
    """
    try:
        trending_data = get_trending_skills(limit)
        
        # Convert to response format
        skills = []
        for skill in trending_data or []:
            skills.append(SkillResponse(
                id=skill['id'],
                name=skill['name'],
                description=f"Trending skill with {skill.get('avg_growth_rate', 0):.1f}% growth rate",
                category=skill.get('category'),
                is_hot_technology=True,  # Trending skills are considered hot
                is_in_demand=True
            ))
        
        return skills
        
    except Exception as e:
        logger.error(f"Error getting trending skills: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving trending skills"
        )

@router.get("/jobs",
            response_model=List[JobProfessionResponse],
            responses={
                200: {"description": "List of all job professions"}
            })
async def get_jobs(
    category: Optional[str] = Query(None, description="Filter by job category"),
    limit: Optional[int] = Query(50, description="Maximum number of jobs to return")
):
    """
    Get all available job professions with optional filtering
    
    - **category**: Filter by job category (Data & Analytics, Software Development, etc.)
    - **limit**: Maximum number of jobs to return (default: 50)
    """
    try:
        from ..utils.database import db_manager
        
        # Build query with filters
        query = """
            SELECT id, name, description, category
            FROM job_professions
            WHERE 1=1
        """
        params = []
        
        if category:
            query += " AND category = %s"
            params.append(category)
        
        query += " ORDER BY name LIMIT %s"
        params.append(limit)
        
        jobs_data = db_manager.execute_query(query, tuple(params), fetch='all')
        
        # Convert to response format
        jobs = []
        for job in jobs_data or []:
            jobs.append(JobProfessionResponse(
                id=job['id'],
                name=job['name'],
                description=job.get('description'),
                category=job.get('category')
            ))
        
        return jobs
        
    except Exception as e:
        logger.error(f"Error getting jobs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving jobs"
        )

@router.get("/jobs/categories",
            response_model=List[str],
            responses={
                200: {"description": "List of job categories"}
            })
async def get_job_categories():
    """
    Get all available job categories
    
    Returns unique list of job categories
    """
    try:
        from ..utils.database import db_manager
        
        query = "SELECT DISTINCT category FROM job_professions WHERE category IS NOT NULL ORDER BY category"
        categories_data = db_manager.execute_query(query, fetch='all')
        
        categories = [cat['category'] for cat in categories_data or []]
        return categories
        
    except Exception as e:
        logger.error(f"Error getting job categories: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving job categories"
        )

@router.get("/jobs/{job_id}",
            response_model=JobWithSkillsResponse,
            responses={
                404: {"model": ErrorResponse, "description": "Job not found"}
            })
async def get_job_details(job_id: str):
    """
    Get detailed information about a specific job including required skills
    
    - **job_id**: ID of the job profession
    """
    try:
        from ..utils.database import db_manager
        
        # Get job info
        job_query = "SELECT * FROM job_professions WHERE id = %s"
        job_data = db_manager.execute_query(job_query, (job_id,), fetch='one')
        
        if not job_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found"
            )
        
        # Get required skills
        skills_data = get_job_required_skills(job_id)
        
        # Convert to response format
        required_skills = []
        for skill in skills_data or []:
            skill_response = SkillResponse(
                id=skill['id'],
                name=skill['name'],
                description=skill.get('description'),
                category=skill.get('category'),
                is_hot_technology=bool(skill.get('is_hot_technology', False)),
                is_in_demand=bool(skill.get('is_in_demand', False))
            )
            
            required_skills.append(JobSkillRequirement(
                id=skill.get('requirement_id', skill['id']),  # Use requirement ID if available
                skill=skill_response,
                importance_level=skill.get('importance_level', 'Important'),
                task_description=skill.get('task_description')
            ))
        
        return JobWithSkillsResponse(
            id=job_data['id'],
            name=job_data['name'],
            description=job_data.get('description'),
            category=job_data.get('category'),
            required_skills=required_skills,
            total_skills=len(required_skills)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job details: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving job details"
        )

@router.post("/search/skills",
             response_model=SkillSearchResponse,
             responses={
                 400: {"model": ErrorResponse, "description": "Invalid search query"}
             })
async def search_skills_endpoint(search_data: SearchRequest):
    """
    Search for skills by name or description
    
    - **query**: Search term to look for in skill names and descriptions
    - **limit**: Maximum number of results to return
    """
    try:
        skills_data = search_skills(search_data.query)
        
        # Apply limit
        limited_skills = skills_data[:search_data.limit] if skills_data else []
        
        # Convert to response format
        skills = []
        for skill in limited_skills:
            skills.append(SkillResponse(
                id=skill['id'],
                name=skill['name'],
                description=skill.get('description'),
                category=skill.get('category'),
                is_hot_technology=bool(skill.get('is_hot_technology', False)),
                is_in_demand=bool(skill.get('is_in_demand', False))
            ))
        
        return SkillSearchResponse(
            skills=skills,
            total_found=len(skills_data) if skills_data else 0
        )
        
    except Exception as e:
        logger.error(f"Error searching skills: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error searching skills"
        )

@router.post("/search/jobs",
             response_model=JobSearchResponse,
             responses={
                 400: {"model": ErrorResponse, "description": "Invalid search query"}
             })
async def search_jobs_endpoint(search_data: SearchRequest):
    """
    Search for job professions by name or description
    
    - **query**: Search term to look for in job names and descriptions
    - **limit**: Maximum number of results to return
    """
    try:
        jobs_data = search_jobs(search_data.query)
        
        # Apply limit
        limited_jobs = jobs_data[:search_data.limit] if jobs_data else []
        
        # Convert to response format
        jobs = []
        for job in limited_jobs:
            jobs.append(JobProfessionResponse(
                id=job['id'],
                name=job['name'],
                description=job.get('description'),
                category=job.get('category')
            ))
        
        return JobSearchResponse(
            jobs=jobs,
            total_found=len(jobs_data) if jobs_data else 0
        )
        
    except Exception as e:
        logger.error(f"Error searching jobs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error searching jobs"
        )

@router.get("/professions/autocomplete",
            response_model=List[str],
            responses={
                200: {"description": "List of profession names matching the query"}
            })
async def autocomplete_professions(
    query: str = Query(..., min_length=1, description="Search query for profession names"),
    limit: Optional[int] = Query(10, description="Maximum number of suggestions to return")
):
    """
    Get profession name suggestions for autocomplete based on skills database
    
    - **query**: Text to search for in profession names (case-insensitive)
    - **limit**: Maximum number of suggestions to return (default: 10)
    
    This endpoint searches through the job_professions table and returns matching
    profession names for autocomplete functionality.
    """
    try:
        from ..utils.database import db_manager
        
        # Search in the job_professions table for professions starting with the query
        search_query = """
            SELECT DISTINCT name as profession_name
            FROM job_professions 
            WHERE name LIKE %s
            ORDER BY name
            LIMIT %s
        """
        
        # Create search pattern - starts with the query (case-insensitive)
        search_pattern = f"{query}%"
        
        results = db_manager.execute_query(
            search_query, 
            (search_pattern, limit), 
            fetch='all'
        )
        
        # Extract profession names
        professions = []
        if results:
            for row in results:
                profession_name = row['profession_name']
                if profession_name and profession_name.strip():
                    professions.append(profession_name.strip())
        
        # Remove duplicates while preserving order (shouldn't be needed but just in case)
        seen = set()
        unique_professions = []
        for prof in professions:
            if prof.lower() not in seen:
                seen.add(prof.lower())
                unique_professions.append(prof)
        
        return unique_professions[:limit]
        
    except Exception as e:
        logger.error(f"Error in profession autocomplete: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving profession suggestions"
        )

@router.get("/stats",
            response_model=dict,
            responses={
                200: {"description": "Skills and jobs statistics"}
            })
async def get_skills_jobs_stats():
    """
    Get statistics about skills and jobs in the system
    
    Returns counts and distribution information
    """
    try:
        from ..utils.database import db_manager
        
        # Get skills stats
        skills_stats_query = """
            SELECT 
                COUNT(*) as total_skills,
                COUNT(CASE WHEN is_hot_technology = TRUE THEN 1 END) as hot_technologies,
                COUNT(CASE WHEN is_in_demand = TRUE THEN 1 END) as in_demand_skills,
                COUNT(DISTINCT category) as skill_categories
            FROM skills
        """
        skills_stats = db_manager.execute_query(skills_stats_query, fetch='one')
        
        # Get jobs stats
        jobs_stats_query = """
            SELECT 
                COUNT(*) as total_jobs,
                COUNT(DISTINCT category) as job_categories
            FROM job_professions
        """
        jobs_stats = db_manager.execute_query(jobs_stats_query, fetch='one')
        
        # Get top skill categories
        top_categories_query = """
            SELECT category, COUNT(*) as count
            FROM skills 
            WHERE category IS NOT NULL
            GROUP BY category
            ORDER BY count DESC
            LIMIT 5
        """
        top_categories = db_manager.execute_query(top_categories_query, fetch='all')
        
        return {
            "skills": {
                "total": skills_stats['total_skills'],
                "hot_technologies": skills_stats['hot_technologies'],
                "in_demand": skills_stats['in_demand_skills'],
                "categories": skills_stats['skill_categories']
            },
            "jobs": {
                "total": jobs_stats['total_jobs'],
                "categories": jobs_stats['job_categories']
            },
            "top_skill_categories": [
                {"category": cat['category'], "count": cat['count']}
                for cat in top_categories or []
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving statistics"
        )
