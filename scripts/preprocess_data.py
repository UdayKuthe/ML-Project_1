#!/usr/bin/env python3
"""
Data Preprocessing Script for Skill Gap Analyzer

This script processes the raw resume dataset and skills database to create
training data for the spaCy NLP model and other ML components.
"""

import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
backend_dir = project_root / "backend"
sys.path.append(str(backend_dir))

from app.services.data_preprocessor import SkillDataPreprocessor

def main():
    """Main preprocessing pipeline"""
    
    # Define paths
    project_root = Path(__file__).resolve().parent.parent
    skills_db_path = project_root / "data" / "raw" / "skills_database.csv"
    resume_data_path = project_root / "data" / "raw" / "UpdatedResumeDataSet.csv"
    output_dir = project_root / "data" / "processed"
    
    print("=== Skill Gap Analyzer Data Preprocessing ===")
    print(f"Skills Database: {skills_db_path}")
    print(f"Resume Dataset: {resume_data_path}")
    print(f"Output Directory: {output_dir}")
    
    # Check if input files exist
    if not skills_db_path.exists():
        print(f"ERROR: Skills database not found at {skills_db_path}")
        return 1
    
    if not resume_data_path.exists():
        print(f"ERROR: Resume dataset not found at {resume_data_path}")
        return 1
    
    try:
        # Initialize preprocessor
        print("\n1. Initializing data preprocessor...")
        preprocessor = SkillDataPreprocessor(
            str(skills_db_path), 
            str(resume_data_path)
        )
        
        # Process all data
        print("\n2. Processing all data...")
        stats = preprocessor.process_all_data(str(output_dir))
        
        # Print summary
        print("\n=== PREPROCESSING SUMMARY ===")
        print(f"Total resumes processed: {stats['total_resumes']}")
        print(f"Unique skills identified: {stats['total_skills']}")
        print(f"Job professions: {stats['total_job_professions']}")
        print(f"Training examples created: {stats['training_examples_created']}")
        
        print("\nResume categories:")
        for category, count in stats['categories'].items():
            print(f"  - {category}: {count}")
        
        print(f"\nProcessed data saved to: {output_dir}")
        print("\nFiles created:")
        print("  - spacy_training_data.json")
        print("  - skill_embeddings.json")
        print("  - job_skill_mapping.json")
        print("  - preprocessing_stats.json")
        
        print("\n✅ Data preprocessing completed successfully!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during preprocessing: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
