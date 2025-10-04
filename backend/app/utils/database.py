"""
Database connection utilities and helper functions
"""

import mysql.connector
from mysql.connector import Error
from contextlib import contextmanager
import logging
from typing import Dict, Any, List, Optional, Generator
import os
from config import Config

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database connection and query management"""
    
    def __init__(self):
        self.connection_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', ''),
            'database': os.getenv('DB_NAME', 'skill_gap_analyzer'),
            'charset': 'utf8mb4',
            'autocommit': True,
            'use_unicode': True
        }
    
    def get_connection(self):
        """Get database connection"""
        try:
            connection = mysql.connector.connect(**self.connection_config)
            return connection
        except Error as e:
            logger.error(f"Error connecting to MySQL: {e}")
            raise
    
    @contextmanager
    def get_db_cursor(self, dictionary=True) -> Generator:
        """Context manager for database cursor"""
        connection = None
        cursor = None
        try:
            connection = self.get_connection()
            cursor = connection.cursor(dictionary=dictionary)
            yield cursor
        except Error as e:
            if connection:
                connection.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def execute_query(self, query: str, params: tuple = None, fetch: str = None) -> Any:
        """
        Execute a database query
        
        Args:
            query: SQL query string
            params: Query parameters
            fetch: 'one', 'all', or None for no fetch
            
        Returns:
            Query results or None
        """
        with self.get_db_cursor() as cursor:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            if fetch == 'one':
                return cursor.fetchone()
            elif fetch == 'all':
                return cursor.fetchall()
            elif fetch == 'many':
                return cursor.fetchmany()
            else:
                return cursor.rowcount
    
    def execute_stored_procedure(self, proc_name: str, params: tuple = ()) -> List[Dict]:
        """Execute a stored procedure"""
        with self.get_db_cursor() as cursor:
            cursor.callproc(proc_name, params)
            
            results = []
            for result in cursor.stored_results():
                results.extend(result.fetchall())
            
            return results
    
    def insert_and_get_id(self, query: str, params: tuple) -> str:
        """Insert record and return the inserted ID"""
        with self.get_db_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.lastrowid

# Database utility functions
db_manager = DatabaseManager()

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email address"""
    query = "SELECT * FROM users WHERE email = %s AND is_active = TRUE"
    return db_manager.execute_query(query, (email,), fetch='one')

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID"""
    query = "SELECT * FROM users WHERE id = %s AND is_active = TRUE"
    return db_manager.execute_query(query, (user_id,), fetch='one')

def create_user(email: str, full_name: str, hashed_password: str) -> str:
    """Create a new user"""
    import uuid
    user_id = str(uuid.uuid4())
    
    query = """
        INSERT INTO users (id, email, full_name, hashed_password, is_active)
        VALUES (%s, %s, %s, %s, TRUE)
    """
    db_manager.execute_query(query, (user_id, email, full_name, hashed_password))
    return user_id

def get_all_skills() -> List[Dict[str, Any]]:
    """Get all skills from database"""
    query = """
        SELECT id, name, description, category, is_hot_technology, is_in_demand
        FROM skills
        ORDER BY name
    """
    return db_manager.execute_query(query, fetch='all')

def get_all_job_professions() -> List[Dict[str, Any]]:
    """Get all job professions from database"""
    query = """
        SELECT id, name, description, category
        FROM job_professions
        ORDER BY name
    """
    return db_manager.execute_query(query, fetch='all')

def get_job_required_skills(job_id: str) -> List[Dict[str, Any]]:
    """Get skills required for a specific job"""
    return db_manager.execute_stored_procedure('GetJobRequiredSkills', (job_id,))

def search_jobs(search_term: str) -> List[Dict[str, Any]]:
    """Search job professions"""
    return db_manager.execute_stored_procedure('SearchJobs', (search_term,))

def search_skills(search_term: str) -> List[Dict[str, Any]]:
    """Search skills"""
    return db_manager.execute_stored_procedure('SearchSkills', (search_term,))

def save_resume(user_id: str, filename: str, file_path: str, raw_text: str, 
                file_size: int, mime_type: str) -> str:
    """Save resume to database"""
    import uuid
    resume_id = str(uuid.uuid4())
    
    query = """
        INSERT INTO resumes (id, user_id, filename, file_path, raw_text, file_size, mime_type, processed)
        VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE)
    """
    db_manager.execute_query(query, (resume_id, user_id, filename, file_path, raw_text, file_size, mime_type))
    return resume_id

def save_resume_skills(resume_id: str, skills_data: List[Dict]) -> int:
    """Save extracted skills for a resume"""
    count = 0
    for skill_data in skills_data:
        import uuid
        skill_id = str(uuid.uuid4())
        
        query = """
            INSERT INTO resume_skills (id, resume_id, skill_id, original_text, confidence_score, 
                                     match_type, position_start, position_end)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            skill_id,
            resume_id,
            skill_data['skill_id'],
            skill_data['original_text'],
            skill_data['confidence_score'],
            skill_data['match_type'],
            skill_data.get('position_start'),
            skill_data.get('position_end')
        )
        db_manager.execute_query(query, params)
        count += 1
    
    return count

def save_skill_analysis(user_id: str, resume_id: str, target_job_id: str, 
                       analysis_results: Dict, visualizations: Dict) -> str:
    """Save skill gap analysis results"""
    import uuid
    import json
    
    analysis_id = str(uuid.uuid4())
    
    query = """
        INSERT INTO skill_analyses (id, user_id, resume_id, target_job_id, proficiency_score,
                                  total_required_skills, skills_present, analysis_results, visualizations)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    params = (
        analysis_id,
        user_id,
        resume_id,
        target_job_id,
        analysis_results['proficiency_score'],
        analysis_results['total_required_skills'],
        analysis_results['skills_present'],
        json.dumps(analysis_results),
        json.dumps(visualizations)
    )
    db_manager.execute_query(query, params)
    return analysis_id

def get_user_analyses(user_id: str) -> List[Dict[str, Any]]:
    """Get all analyses for a user"""
    return db_manager.execute_stored_procedure('GetUserSkillAnalyses', (user_id,))

def save_course_recommendations(analysis_id: str, recommendations: List[Dict]) -> int:
    """Save course recommendations"""
    count = 0
    for rec in recommendations:
        import uuid
        rec_id = str(uuid.uuid4())
        
        query = """
            INSERT INTO course_recommendations (id, analysis_id, skill_name, course_title,
                                              course_provider, course_url, course_description,
                                              estimated_duration, difficulty_level, rating, price,
                                              recommendation_score, priority)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            rec_id,
            analysis_id,
            rec['skill_name'],
            rec['course_title'],
            rec['course_provider'],
            rec['course_url'],
            rec['course_description'],
            rec['estimated_duration'],
            rec['difficulty_level'],
            rec['rating'],
            rec['price'],
            rec['recommendation_score'],
            rec['priority']
        )
        db_manager.execute_query(query, params)
        count += 1
    
    return count

def get_course_recommendations(analysis_id: str) -> List[Dict[str, Any]]:
    """Get course recommendations for an analysis"""
    return db_manager.execute_stored_procedure('GetCourseRecommendations', (analysis_id,))

def update_resume_processed_status(resume_id: str, processed: bool = True):
    """Update resume processed status"""
    query = "UPDATE resumes SET processed = %s WHERE id = %s"
    db_manager.execute_query(query, (processed, resume_id))

def get_skill_by_name(skill_name: str) -> Optional[Dict[str, Any]]:
    """Get skill by name"""
    query = "SELECT * FROM skills WHERE name = %s"
    return db_manager.execute_query(query, (skill_name,), fetch='one')

def get_trending_skills(limit: int = 20) -> List[Dict[str, Any]]:
    """Get trending skills"""
    query = "SELECT * FROM v_trending_skills LIMIT %s"
    return db_manager.execute_query(query, (limit,), fetch='all')

def get_user_dashboard_data(user_id: str) -> Dict[str, Any]:
    """Get user dashboard statistics"""
    results = db_manager.execute_stored_procedure('GetUserDashboardData', (user_id,))
    
    dashboard_data = {}
    for row in results:
        dashboard_data[row['data_type']] = row['count']
    
    return dashboard_data
