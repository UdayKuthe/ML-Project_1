"""
Resume management API endpoints
"""

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File, BackgroundTasks
import logging
from datetime import datetime
import asyncio
import time
from typing import List

from ..models.schemas import (
    ResumeUploadResponse, ResumeProcessingResult, ExtractedSkill, ErrorResponse,
    SuccessResponse, MessageResponse
)
from ..utils.auth import get_current_user
from ..utils.file_processor import save_resume_file, extract_resume_text
from ..utils.database import (
    save_resume, update_resume_processed_status, save_resume_skills,
    get_skill_by_name, get_all_skills
)
from ..services.spacy_trainer import SkillExtractor
from ..services.skill_analyzer import SkillGapAnalyzer
from config import Config

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/resumes", tags=["Resume Management"])

# Initialize skill extractor (will be loaded when first needed)
skill_extractor = None

def get_skill_extractor():
    """Get or initialize skill extractor"""
    global skill_extractor
    if skill_extractor is None:
        try:
            skill_extractor = SkillExtractor(Config.SPACY_MODEL_PATH)
            logger.info("Skill extractor initialized successfully")
        except Exception as e:
            logger.warning(f"Could not load spaCy model, using fallback: {e}")
            # Fallback to basic skill matching if spaCy model not available
            skill_extractor = None
    return skill_extractor

async def process_resume_skills(resume_id: str, resume_text: str):
    """Background task to process resume and extract skills"""
    try:
        start_time = time.time()
        
        # Get skill extractor
        extractor = get_skill_extractor()
        
        extracted_skills = []
        skills_data = []
        
        if extractor:
            # Use trained spaCy model
            raw_skills = extractor.extract_skills(resume_text)
            
            # Convert to database format
            for skill_info in raw_skills:
                # Find skill in database
                skill_record = get_skill_by_name(skill_info['text'])
                if skill_record:
                    skills_data.append({
                        'skill_id': skill_record['id'],
                        'original_text': skill_info['text'],
                        'confidence_score': skill_info['confidence'],
                        'match_type': 'exact',
                        'position_start': skill_info.get('start'),
                        'position_end': skill_info.get('end')
                    })
                    
                    extracted_skills.append(ExtractedSkill(
                        text=skill_info['text'],
                        skill_name=skill_record['name'],
                        confidence_score=skill_info['confidence'],
                        match_type='exact',
                        position_start=skill_info.get('start'),
                        position_end=skill_info.get('end')
                    ))
        else:
            # Fallback: Simple keyword matching
            all_skills = get_all_skills()
            resume_text_lower = resume_text.lower()
            
            for skill_record in all_skills:
                skill_name_lower = skill_record['name'].lower()
                if skill_name_lower in resume_text_lower:
                    # Find position in text
                    start_pos = resume_text_lower.find(skill_name_lower)
                    
                    skills_data.append({
                        'skill_id': skill_record['id'],
                        'original_text': skill_record['name'],
                        'confidence_score': 0.9,  # High confidence for exact match
                        'match_type': 'exact',
                        'position_start': start_pos,
                        'position_end': start_pos + len(skill_name_lower)
                    })
                    
                    extracted_skills.append(ExtractedSkill(
                        text=skill_record['name'],
                        skill_name=skill_record['name'],
                        confidence_score=0.9,
                        match_type='exact',
                        position_start=start_pos,
                        position_end=start_pos + len(skill_name_lower)
                    ))
        
        # Save extracted skills to database
        saved_count = save_resume_skills(resume_id, skills_data)
        
        # Update resume as processed
        update_resume_processed_status(resume_id, True)
        
        processing_time = time.time() - start_time
        
        logger.info(f"Resume {resume_id} processed: {saved_count} skills found in {processing_time:.2f}s")
        
    except Exception as e:
        logger.error(f"Error processing resume {resume_id}: {e}")
        # Mark as processed even if there was an error to prevent infinite retrying
        update_resume_processed_status(resume_id, True)

@router.post("/upload",
             response_model=ResumeUploadResponse,
             status_code=status.HTTP_201_CREATED,
             responses={
                 400: {"model": ErrorResponse, "description": "Invalid file"},
                 413: {"model": ErrorResponse, "description": "File too large"}
             })
async def upload_resume(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Upload a resume file and start processing
    
    - **file**: Resume file (PDF, DOCX, DOC, or TXT)
    - Automatically extracts text and identifies skills
    - Returns immediately with processing started in background
    """
    try:
        # Validate file type and size
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No filename provided"
            )
        
        # Save file to disk
        file_info = save_resume_file(file, current_user["id"])
        
        # Extract text from file
        raw_text = extract_resume_text(file_info["file_path"], file_info["mime_type"])
        
        if not raw_text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not extract text from file. Please ensure the file is not corrupted."
            )
        
        # Save resume to database
        resume_id = save_resume(
            user_id=current_user["id"],
            filename=file_info["original_filename"],
            file_path=file_info["file_path"],
            raw_text=raw_text,
            file_size=file_info["file_size"],
            mime_type=file_info["mime_type"]
        )
        
        # Start background processing
        background_tasks.add_task(process_resume_skills, resume_id, raw_text)
        
        logger.info(f"Resume uploaded by user {current_user['id']}: {file.filename}")
        
        return ResumeUploadResponse(
            resume_id=resume_id,
            filename=file_info["original_filename"],
            file_size=file_info["file_size"],
            mime_type=file_info["mime_type"],
            text_extracted=True,
            processing_started=True,
            message="Resume uploaded successfully. Skill extraction is being processed in the background."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading resume: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing resume upload"
        )

@router.get("/{resume_id}/status",
            response_model=ResumeProcessingResult,
            responses={
                404: {"model": ErrorResponse, "description": "Resume not found"}
            })
async def get_resume_processing_status(
    resume_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get processing status and extracted skills for a resume
    
    - **resume_id**: ID of the uploaded resume
    - Returns processing status and list of extracted skills
    """
    try:
        # Get resume from database
        from ..utils.database import db_manager
        
        resume_query = """
            SELECT r.*, COUNT(rs.id) as skills_count
            FROM resumes r
            LEFT JOIN resume_skills rs ON r.id = rs.resume_id
            WHERE r.id = %s AND r.user_id = %s
            GROUP BY r.id
        """
        resume_data = db_manager.execute_query(resume_query, (resume_id, current_user["id"]), fetch='one')
        
        if not resume_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found"
            )
        
        # Get extracted skills
        skills_query = """
            SELECT rs.*, s.name as skill_name
            FROM resume_skills rs
            JOIN skills s ON rs.skill_id = s.id
            WHERE rs.resume_id = %s
            ORDER BY rs.confidence_score DESC
        """
        skills_data = db_manager.execute_query(skills_query, (resume_id,), fetch='all')
        
        # Convert to response format
        extracted_skills = []
        for skill in skills_data or []:
            extracted_skills.append(ExtractedSkill(
                text=skill['original_text'],
                skill_name=skill['skill_name'],
                confidence_score=float(skill['confidence_score']),
                match_type=skill['match_type'],
                position_start=skill.get('position_start'),
                position_end=skill.get('position_end')
            ))
        
        return ResumeProcessingResult(
            resume_id=resume_id,
            processed=bool(resume_data['processed']),
            skills_found=int(resume_data.get('skills_count', 0)),
            extracted_skills=extracted_skills,
            processing_time_seconds=0.0  # We don't track this currently
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting resume status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving resume status"
        )

@router.get("/",
            response_model=List[dict],
            responses={
                200: {"description": "List of user's resumes"}
            })
async def get_user_resumes(current_user: dict = Depends(get_current_user)):
    """
    Get all resumes uploaded by the current user
    
    Returns list of resumes with basic information
    """
    try:
        from ..utils.database import db_manager
        
        query = """
            SELECT 
                r.id,
                r.filename,
                r.file_size,
                r.processed,
                r.created_at,
                COUNT(rs.id) as skills_count
            FROM resumes r
            LEFT JOIN resume_skills rs ON r.id = rs.resume_id
            WHERE r.user_id = %s
            GROUP BY r.id, r.filename, r.file_size, r.processed, r.created_at
            ORDER BY r.created_at DESC
        """
        
        resumes = db_manager.execute_query(query, (current_user["id"],), fetch='all')
        
        return resumes or []
        
    except Exception as e:
        logger.error(f"Error getting user resumes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving resumes"
        )

@router.delete("/{resume_id}",
               response_model=SuccessResponse,
               responses={
                   404: {"model": ErrorResponse, "description": "Resume not found"}
               })
async def delete_resume(
    resume_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a resume and its associated data
    
    - **resume_id**: ID of the resume to delete
    - Removes file from disk and all database records
    """
    try:
        from ..utils.database import db_manager
        from ..utils.file_processor import file_processor
        
        # Get resume info
        resume_query = "SELECT * FROM resumes WHERE id = %s AND user_id = %s"
        resume = db_manager.execute_query(resume_query, (resume_id, current_user["id"]), fetch='one')
        
        if not resume:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found"
            )
        
        # Delete file from disk
        if resume.get('file_path'):
            file_processor.delete_file(resume['file_path'])
        
        # Delete from database (cascade will handle related records)
        delete_query = "DELETE FROM resumes WHERE id = %s AND user_id = %s"
        db_manager.execute_query(delete_query, (resume_id, current_user["id"]))
        
        logger.info(f"Resume deleted: {resume_id} by user {current_user['id']}")
        
        return SuccessResponse(
            message="Resume deleted successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting resume: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error deleting resume"
        )

@router.post("/{resume_id}/reprocess",
             response_model=MessageResponse,
             responses={
                 404: {"model": ErrorResponse, "description": "Resume not found"}
             })
async def reprocess_resume(
    resume_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Reprocess a resume to extract skills again
    
    - **resume_id**: ID of the resume to reprocess
    - Useful if the skill extraction model has been updated
    """
    try:
        from ..utils.database import db_manager
        
        # Get resume
        resume_query = "SELECT * FROM resumes WHERE id = %s AND user_id = %s"
        resume = db_manager.execute_query(resume_query, (resume_id, current_user["id"]), fetch='one')
        
        if not resume:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resume not found"
            )
        
        # Clear existing skills
        delete_skills_query = "DELETE FROM resume_skills WHERE resume_id = %s"
        db_manager.execute_query(delete_skills_query, (resume_id,))
        
        # Mark as not processed
        update_resume_processed_status(resume_id, False)
        
        # Start reprocessing
        background_tasks.add_task(process_resume_skills, resume_id, resume['raw_text'])
        
        logger.info(f"Resume reprocessing started: {resume_id}")
        
        return MessageResponse(
            message="Resume reprocessing started",
            details={"resume_id": resume_id, "status": "processing"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reprocessing resume: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error reprocessing resume"
        )
