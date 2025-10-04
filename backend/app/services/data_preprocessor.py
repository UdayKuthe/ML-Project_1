import pandas as pd
import json
import re
import spacy
from typing import List, Dict, Tuple, Any
from pathlib import Path
import logging
from fuzzywuzzy import fuzz
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SkillDataPreprocessor:
    def __init__(self, skills_db_path: str, resume_data_path: str):
        """
        Initialize the data preprocessor
        
        Args:
            skills_db_path: Path to the skills database CSV
            resume_data_path: Path to the resume dataset CSV
        """
        self.skills_db_path = skills_db_path
        self.resume_data_path = resume_data_path
        self.skills_df = None
        self.resume_df = None
        self.skill_list = []
        
        # Load sentence transformer for skill matching
        self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        self.load_data()
    
    def load_data(self):
        """Load the skills database and resume dataset"""
        try:
            self.skills_df = pd.read_csv(self.skills_db_path)
            self.resume_df = pd.read_csv(self.resume_data_path)
            
            # Extract unique skills from skills database
            self.skill_list = self.skills_df['Skills'].unique().tolist()
            
            logger.info(f"Loaded {len(self.skills_df)} skill entries")
            logger.info(f"Loaded {len(self.resume_df)} resume entries")
            logger.info(f"Found {len(self.skill_list)} unique skills")
            
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        if pd.isna(text):
            return ""
        
        # Remove extra whitespace and normalize
        text = re.sub(r'\s+', ' ', str(text).strip())
        
        # Remove special characters but keep important punctuation
        text = re.sub(r'[^\w\s\.\-\+\#]', ' ', text)
        
        return text
    
    def extract_skills_from_text(self, text: str, threshold: float = 0.8) -> List[Dict]:
        """
        Extract skills from text using fuzzy matching and semantic similarity
        
        Args:
            text: Input text to extract skills from
            threshold: Similarity threshold for skill matching
            
        Returns:
            List of extracted skills with positions
        """
        text = self.clean_text(text)
        extracted_skills = []
        
        # Tokenize text into words and phrases
        words = text.split()
        
        # Check for exact and fuzzy matches
        for skill in self.skill_list:
            skill_clean = self.clean_text(skill.lower())
            text_lower = text.lower()
            
            # Exact match
            if skill_clean in text_lower:
                start = text_lower.find(skill_clean)
                end = start + len(skill_clean)
                extracted_skills.append({
                    'text': skill,
                    'start': start,
                    'end': end,
                    'label': 'SKILL',
                    'confidence': 1.0
                })
            else:
                # Fuzzy matching for similar skills
                for i, word_group in enumerate(self._get_word_groups(words, len(skill_clean.split()))):
                    word_group_text = ' '.join(word_group).lower()
                    
                    # Check fuzzy similarity
                    fuzzy_score = fuzz.ratio(skill_clean, word_group_text) / 100.0
                    
                    if fuzzy_score >= threshold:
                        # Calculate position in original text
                        start_pos = text_lower.find(word_group_text)
                        if start_pos != -1:
                            extracted_skills.append({
                                'text': skill,
                                'start': start_pos,
                                'end': start_pos + len(word_group_text),
                                'label': 'SKILL',
                                'confidence': fuzzy_score
                            })
        
        # Remove duplicates and overlapping matches
        extracted_skills = self._remove_overlapping_skills(extracted_skills)
        
        return extracted_skills
    
    def _get_word_groups(self, words: List[str], max_length: int) -> List[List[str]]:
        """Generate word groups of different lengths"""
        groups = []
        for length in range(1, min(max_length + 1, 6)):  # Max 5 words per skill
            for i in range(len(words) - length + 1):
                groups.append(words[i:i + length])
        return groups
    
    def _remove_overlapping_skills(self, skills: List[Dict]) -> List[Dict]:
        """Remove overlapping skill matches, keeping the highest confidence"""
        if not skills:
            return skills
        
        # Sort by confidence descending
        skills = sorted(skills, key=lambda x: x['confidence'], reverse=True)
        
        filtered_skills = []
        for skill in skills:
            # Check for overlap with already accepted skills
            overlap = False
            for accepted in filtered_skills:
                if (skill['start'] < accepted['end'] and 
                    skill['end'] > accepted['start']):
                    overlap = True
                    break
            
            if not overlap:
                filtered_skills.append(skill)
        
        return filtered_skills
    
    def create_spacy_training_data(self, output_path: str):
        """
        Convert resume data to spaCy training format
        
        Args:
            output_path: Path to save the training data
        """
        training_data = []
        
        logger.info("Creating spaCy training data...")
        
        for idx, row in self.resume_df.iterrows():
            resume_text = self.clean_text(row['Resume'])
            
            if len(resume_text.strip()) == 0:
                continue
            
            # Extract skills from resume text
            skills = self.extract_skills_from_text(resume_text)
            
            if skills:
                # Create entities list for spaCy
                entities = [(skill['start'], skill['end'], skill['label']) 
                           for skill in skills]
                
                training_data.append({
                    'text': resume_text,
                    'entities': entities,
                    'category': row.get('Category', 'Unknown')
                })
            
            if (idx + 1) % 100 == 0:
                logger.info(f"Processed {idx + 1} resumes")
        
        # Save training data
        output_file = Path(output_path) / 'spacy_training_data.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(training_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Created {len(training_data)} training examples")
        logger.info(f"Training data saved to {output_file}")
        
        return training_data
    
    def create_skill_embeddings(self, output_path: str):
        """Create embeddings for all skills for semantic matching"""
        logger.info("Creating skill embeddings...")
        
        # Clean skill names
        clean_skills = [self.clean_text(skill) for skill in self.skill_list]
        
        # Generate embeddings
        embeddings = self.sentence_model.encode(clean_skills)
        
        # Create skill-embedding mapping
        skill_embeddings = {
            'skills': self.skill_list,
            'clean_skills': clean_skills,
            'embeddings': embeddings.tolist()
        }
        
        # Save embeddings
        output_file = Path(output_path) / 'skill_embeddings.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(skill_embeddings, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Created embeddings for {len(self.skill_list)} skills")
        logger.info(f"Embeddings saved to {output_file}")
        
        return skill_embeddings
    
    def create_job_skill_mapping(self, output_path: str):
        """Create mapping between job professions and required skills"""
        logger.info("Creating job-skill mapping...")
        
        job_skills = {}
        
        for _, row in self.skills_df.iterrows():
            job_profession = row['Job Profession']
            skill = row['Skills']
            task = row.get('Tasks he wanted to learn', '')
            hot_tech = row.get('Hot Technology', 'N') == 'Y'
            in_demand = row.get('In Demand', 'N') == 'Y'
            
            if job_profession not in job_skills:
                job_skills[job_profession] = {
                    'skills': [],
                    'tasks': [],
                    'hot_technologies': [],
                    'in_demand_skills': []
                }
            
            skill_info = {
                'skill': skill,
                'task': task,
                'is_hot_tech': hot_tech,
                'is_in_demand': in_demand
            }
            
            job_skills[job_profession]['skills'].append(skill_info)
            
            if task and task not in job_skills[job_profession]['tasks']:
                job_skills[job_profession]['tasks'].append(task)
            
            if hot_tech:
                job_skills[job_profession]['hot_technologies'].append(skill)
            
            if in_demand:
                job_skills[job_profession]['in_demand_skills'].append(skill)
        
        # Save job-skill mapping
        output_file = Path(output_path) / 'job_skill_mapping.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(job_skills, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Created mapping for {len(job_skills)} job professions")
        logger.info(f"Job-skill mapping saved to {output_file}")
        
        return job_skills
    
    def process_all_data(self, output_dir: str):
        """Process all data and create all necessary files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create spaCy training data
        training_data = self.create_spacy_training_data(output_path)
        
        # Create skill embeddings
        embeddings = self.create_skill_embeddings(output_path)
        
        # Create job-skill mapping
        job_mapping = self.create_job_skill_mapping(output_path)
        
        # Create summary statistics
        stats = {
            'total_resumes': len(self.resume_df),
            'total_skills': len(self.skill_list),
            'total_job_professions': len(self.skills_df['Job Profession'].unique()),
            'training_examples_created': len(training_data),
            'categories': self.resume_df['Category'].value_counts().to_dict()
        }
        
        stats_file = output_path / 'preprocessing_stats.json'
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        logger.info("Data preprocessing completed successfully!")
        logger.info(f"Statistics saved to {stats_file}")
        
        return stats

if __name__ == "__main__":
    # Example usage
    skills_db_path = "../../data/raw/skills_database.csv"
    resume_data_path = "../../data/raw/UpdatedResumeDataSet.csv"
    output_dir = "../../data/processed"
    
    preprocessor = SkillDataPreprocessor(skills_db_path, resume_data_path)
    stats = preprocessor.process_all_data(output_dir)
