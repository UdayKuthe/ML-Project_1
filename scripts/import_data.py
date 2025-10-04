#!/usr/bin/env python3
"""
Data Import Script for Skill Gap Analyzer

This script imports the actual CSV data (skills and job professions) 
into the MySQL database.
"""

import pandas as pd
import mysql.connector
from mysql.connector import Error
import uuid
import sys
import os
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataImporter:
    def __init__(self, db_config):
        """
        Initialize database connection
        
        Args:
            db_config: Dictionary with database connection parameters
        """
        self.db_config = db_config
        self.connection = None
        self.cursor = None
        
    def connect(self):
        """Connect to MySQL database"""
        try:
            self.connection = mysql.connector.connect(**self.db_config)
            self.cursor = self.connection.cursor()
            logger.info("Connected to MySQL database successfully")
            return True
        except Error as e:
            logger.error(f"Error connecting to MySQL: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from database"""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        logger.info("Disconnected from database")
    
    def execute_query(self, query, params=None, fetch=False):
        """Execute a SQL query"""
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
                
            if fetch:
                return self.cursor.fetchall()
            else:
                self.connection.commit()
                return True
        except Error as e:
            logger.error(f"Error executing query: {e}")
            self.connection.rollback()
            return False
    
    def load_skills_data(self, csv_path):
        """Load skills database from CSV"""
        try:
            # Read CSV file
            df = pd.read_csv(csv_path)
            logger.info(f"Loaded CSV with {len(df)} rows")
            
            # Clean column names (remove extra spaces)
            df.columns = df.columns.str.strip()
            
            # Display column names for debugging
            logger.info(f"CSV columns: {list(df.columns)}")
            
            return df
        except Exception as e:
            logger.error(f"Error loading CSV: {e}")
            return None
    
    def categorize_skill(self, skill_name):
        """Categorize skills based on their names"""
        skill_lower = skill_name.lower()
        
        programming_keywords = ['python', 'java', 'javascript', 'sql', 'c++', 'c#', 'php', 'ruby', 'go', 'kotlin']
        ml_keywords = ['machine learning', 'deep learning', 'tensorflow', 'scikit', 'pytorch', 'neural', 'ai']
        web_keywords = ['html', 'css', 'react', 'angular', 'vue', 'node.js', 'express', 'bootstrap']
        database_keywords = ['mysql', 'postgresql', 'mongodb', 'database', 'oracle', 'redis', 'sqlite']
        cloud_keywords = ['aws', 'azure', 'cloud', 'docker', 'kubernetes', 'gcp', 'heroku']
        data_keywords = ['tableau', 'power bi', 'excel', 'analytics', 'pandas', 'numpy', 'matplotlib']
        
        if any(keyword in skill_lower for keyword in programming_keywords):
            return 'Programming Languages'
        elif any(keyword in skill_lower for keyword in ml_keywords):
            return 'Machine Learning/AI'
        elif any(keyword in skill_lower for keyword in web_keywords):
            return 'Web Technologies'
        elif any(keyword in skill_lower for keyword in database_keywords):
            return 'Database'
        elif any(keyword in skill_lower for keyword in cloud_keywords):
            return 'Cloud & DevOps'
        elif any(keyword in skill_lower for keyword in data_keywords):
            return 'Data Analysis'
        else:
            return 'Other'
    
    def categorize_job(self, job_name):
        """Categorize job professions based on their names"""
        job_lower = job_name.lower()
        
        if any(keyword in job_lower for keyword in ['data', 'analyst', 'scientist']):
            return 'Data & Analytics'
        elif any(keyword in job_lower for keyword in ['software', 'developer', 'engineer', 'programmer']):
            return 'Software Development'
        elif any(keyword in job_lower for keyword in ['manager', 'director', 'executive', 'chief']):
            return 'Management'
        elif any(keyword in job_lower for keyword in ['marketing', 'sales']):
            return 'Marketing & Sales'
        else:
            return 'Other'
    
    def import_skills(self, df):
        """Import unique skills into database"""
        logger.info("Importing skills...")
        
        # Get unique skills
        unique_skills = df['Skills'].dropna().unique()
        
        skills_data = []
        for skill in unique_skills:
            skill = str(skill).strip()
            if skill and skill != 'nan':
                # Get hot_technology and in_demand info for this skill
                skill_rows = df[df['Skills'] == skill]
                is_hot_tech = any(skill_rows['Hot Technology'] == 'Y')
                is_in_demand = any(skill_rows['In Demand'] == 'Y')
                
                skills_data.append({
                    'id': str(uuid.uuid4()),
                    'name': skill,
                    'category': self.categorize_skill(skill),
                    'is_hot_technology': is_hot_tech,
                    'is_in_demand': is_in_demand
                })
        
        # Insert skills
        insert_query = """
            INSERT IGNORE INTO skills (id, name, description, category, is_hot_technology, is_in_demand)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        for skill in skills_data:
            params = (
                skill['id'],
                skill['name'],
                f"Skill used in various professional roles",
                skill['category'],
                skill['is_hot_technology'],
                skill['is_in_demand']
            )
            self.execute_query(insert_query, params)
        
        logger.info(f"Imported {len(skills_data)} unique skills")
        return len(skills_data)
    
    def import_job_professions(self, df):
        """Import unique job professions into database"""
        logger.info("Importing job professions...")
        
        # Get unique job professions
        unique_jobs = df['Job Profession'].dropna().unique()
        
        jobs_data = []
        for job in unique_jobs:
            job = str(job).strip()
            if job and job != 'nan':
                jobs_data.append({
                    'id': str(uuid.uuid4()),
                    'name': job,
                    'category': self.categorize_job(job)
                })
        
        # Insert job professions
        insert_query = """
            INSERT IGNORE INTO job_professions (id, name, description, category)
            VALUES (%s, %s, %s, %s)
        """
        
        for job in jobs_data:
            params = (
                job['id'],
                job['name'],
                f"Professional role requiring various technical and soft skills",
                job['category']
            )
            self.execute_query(insert_query, params)
        
        logger.info(f"Imported {len(jobs_data)} unique job professions")
        return len(jobs_data)
    
    def import_job_skill_requirements(self, df):
        """Import job-skill requirements mapping"""
        logger.info("Creating job-skill requirements mapping...")
        
        # Get job and skill IDs from database
        job_ids = {}
        skill_ids = {}
        
        # Fetch job IDs
        job_query = "SELECT id, name FROM job_professions"
        jobs = self.execute_query(job_query, fetch=True)
        for job_id, job_name in jobs:
            job_ids[job_name.strip()] = job_id
        
        # Fetch skill IDs
        skill_query = "SELECT id, name FROM skills"
        skills = self.execute_query(skill_query, fetch=True)
        for skill_id, skill_name in skills:
            skill_ids[skill_name.strip()] = skill_id
        
        # Create mapping
        mappings_data = []
        for _, row in df.iterrows():
            job_name = str(row['Job Profession']).strip()
            skill_name = str(row['Skills']).strip()
            
            if job_name in job_ids and skill_name in skill_ids:
                hot_tech = str(row.get('Hot Technology', 'N')).strip()
                in_demand = str(row.get('In Demand', 'N')).strip()
                
                # Determine importance level
                if hot_tech == 'Y' and in_demand == 'Y':
                    importance = 'Critical'
                elif hot_tech == 'Y' or in_demand == 'Y':
                    importance = 'Important'
                else:
                    importance = 'Nice-to-have'
                
                mappings_data.append({
                    'id': str(uuid.uuid4()),
                    'job_id': job_ids[job_name],
                    'skill_id': skill_ids[skill_name],
                    'importance_level': importance,
                    'task_description': str(row.get('Tasks he wanted to learn', '')).strip()
                })
        
        # Remove duplicates
        unique_mappings = []
        seen = set()
        for mapping in mappings_data:
            key = (mapping['job_id'], mapping['skill_id'])
            if key not in seen:
                unique_mappings.append(mapping)
                seen.add(key)
        
        # Insert mappings
        insert_query = """
            INSERT IGNORE INTO job_skill_requirements (id, job_id, skill_id, importance_level, task_description)
            VALUES (%s, %s, %s, %s, %s)
        """
        
        for mapping in unique_mappings:
            params = (
                mapping['id'],
                mapping['job_id'],
                mapping['skill_id'],
                mapping['importance_level'],
                mapping['task_description']
            )
            self.execute_query(insert_query, params)
        
        logger.info(f"Created {len(unique_mappings)} job-skill requirement mappings")
        return len(unique_mappings)
    
    def add_sample_users(self):
        """Add sample users for testing"""
        logger.info("Adding sample users...")
        
        users = [
            ('admin@skillgap.com', 'System Administrator'),
            ('demo@skillgap.com', 'Demo User'),
            ('test@skillgap.com', 'Test User')
        ]
        
        # Hash for 'password123' - in production, use proper password hashing
        hashed_password = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj.LzjhKI6F6'
        
        insert_query = """
            INSERT IGNORE INTO users (id, email, full_name, hashed_password, is_active)
            VALUES (%s, %s, %s, %s, %s)
        """
        
        for email, name in users:
            params = (str(uuid.uuid4()), email, name, hashed_password, True)
            self.execute_query(insert_query, params)
        
        logger.info(f"Added {len(users)} sample users")
    
    def print_statistics(self):
        """Print import statistics"""
        logger.info("=== IMPORT STATISTICS ===")
        
        # Skills statistics
        skills_query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_hot_technology = TRUE THEN 1 ELSE 0 END) as hot_tech,
                SUM(CASE WHEN is_in_demand = TRUE THEN 1 ELSE 0 END) as in_demand
            FROM skills
        """
        result = self.execute_query(skills_query, fetch=True)
        if result:
            total, hot_tech, in_demand = result[0]
            logger.info(f"Skills: {total} total, {hot_tech} hot technologies, {in_demand} in-demand")
        
        # Job professions statistics
        jobs_query = "SELECT COUNT(*) FROM job_professions"
        result = self.execute_query(jobs_query, fetch=True)
        if result:
            logger.info(f"Job Professions: {result[0][0]}")
        
        # Mappings statistics
        mappings_query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN importance_level = 'Critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN importance_level = 'Important' THEN 1 ELSE 0 END) as important
            FROM job_skill_requirements
        """
        result = self.execute_query(mappings_query, fetch=True)
        if result:
            total, critical, important = result[0]
            logger.info(f"Job-Skill Mappings: {total} total, {critical} critical, {important} important")

def main():
    """Main import process"""
    
    # Database configuration
    db_config = {
        'host': 'localhost',
        'user': 'root',  # Change this to your MySQL username
        'password': '',  # Change this to your MySQL password
        'database': 'skill_gap_analyzer',
        'charset': 'utf8mb4'
    }
    
    # File paths
    project_root = Path(__file__).resolve().parent.parent
    csv_path = project_root / "data" / "raw" / "skills_database.csv"
    
    if not csv_path.exists():
        logger.error(f"CSV file not found: {csv_path}")
        return 1
    
    # Initialize importer
    importer = DataImporter(db_config)
    
    try:
        # Connect to database
        if not importer.connect():
            return 1
        
        # Load CSV data
        df = importer.load_skills_data(csv_path)
        if df is None:
            return 1
        
        logger.info(f"Loaded {len(df)} rows from CSV")
        
        # Import data
        skills_count = importer.import_skills(df)
        jobs_count = importer.import_job_professions(df)
        mappings_count = importer.import_job_skill_requirements(df)
        
        # Add sample users
        importer.add_sample_users()
        
        # Print statistics
        importer.print_statistics()
        
        logger.info("✅ Data import completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error during import: {e}")
        return 1
    
    finally:
        importer.disconnect()
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
