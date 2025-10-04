import json
import numpy as np
from typing import List, Dict, Tuple, Any, Optional
from pathlib import Path
import logging
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from fuzzywuzzy import fuzz
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SkillGapAnalyzer:
    """
    Advanced skill gap analyzer using semantic similarity and machine learning
    """
    
    def __init__(self, 
                 skill_embeddings_path: str,
                 job_skill_mapping_path: str,
                 sbert_model_name: str = "all-MiniLM-L6-v2",
                 similarity_threshold: float = 0.7):
        """
        Initialize the skill gap analyzer
        
        Args:
            skill_embeddings_path: Path to pre-computed skill embeddings
            job_skill_mapping_path: Path to job-skill mapping JSON
            sbert_model_name: Name of the sentence transformer model
            similarity_threshold: Threshold for skill matching
        """
        self.skill_embeddings_path = skill_embeddings_path
        self.job_skill_mapping_path = job_skill_mapping_path
        self.similarity_threshold = similarity_threshold
        
        # Load SBERT model
        self.sbert_model = SentenceTransformer(sbert_model_name)
        
        # Initialize data structures
        self.skill_embeddings = None
        self.skill_list = []
        self.job_skill_mapping = {}
        
        # Load pre-computed data
        self.load_skill_data()
    
    def load_skill_data(self):
        """Load skill embeddings and job-skill mapping"""
        try:
            # Load skill embeddings
            with open(self.skill_embeddings_path, 'r', encoding='utf-8') as f:
                embedding_data = json.load(f)
            
            self.skill_list = embedding_data['skills']
            self.skill_embeddings = np.array(embedding_data['embeddings'])
            
            logger.info(f"Loaded embeddings for {len(self.skill_list)} skills")
            
            # Load job-skill mapping
            with open(self.job_skill_mapping_path, 'r', encoding='utf-8') as f:
                self.job_skill_mapping = json.load(f)
            
            logger.info(f"Loaded mapping for {len(self.job_skill_mapping)} job professions")
            
        except Exception as e:
            logger.error(f"Error loading skill data: {e}")
            raise
    
    def extract_and_match_skills(self, resume_skills: List[str]) -> List[Dict]:
        """
        Match resume skills to the master skill database using semantic similarity
        
        Args:
            resume_skills: List of skills extracted from resume
            
        Returns:
            List of matched skills with confidence scores
        """
        if not resume_skills:
            return []
        
        matched_skills = []
        
        # Generate embeddings for resume skills
        resume_embeddings = self.sbert_model.encode(resume_skills)
        
        # Calculate similarities
        similarities = cosine_similarity(resume_embeddings, self.skill_embeddings)
        
        for i, resume_skill in enumerate(resume_skills):
            skill_similarities = similarities[i]
            
            # Find best matches
            best_match_idx = np.argmax(skill_similarities)
            best_similarity = skill_similarities[best_match_idx]
            
            # Also check fuzzy matching
            fuzzy_scores = [fuzz.ratio(resume_skill.lower(), skill.lower()) / 100.0 
                           for skill in self.skill_list]
            best_fuzzy_idx = np.argmax(fuzzy_scores)
            best_fuzzy_score = fuzzy_scores[best_fuzzy_idx]
            
            # Use the best of semantic or fuzzy matching
            if best_similarity >= best_fuzzy_score:
                final_match_idx = best_match_idx
                final_score = best_similarity
                match_type = "semantic"
            else:
                final_match_idx = best_fuzzy_idx
                final_score = best_fuzzy_score
                match_type = "fuzzy"
            
            if final_score >= self.similarity_threshold:
                matched_skills.append({
                    "original_skill": resume_skill,
                    "matched_skill": self.skill_list[final_match_idx],
                    "confidence": final_score,
                    "match_type": match_type
                })
        
        return matched_skills
    
    def get_job_required_skills(self, job_profession: str) -> Dict[str, Any]:
        """
        Get required skills for a specific job profession
        
        Args:
            job_profession: Name of the job profession
            
        Returns:
            Dictionary containing required skills and metadata
        """
        if job_profession not in self.job_skill_mapping:
            logger.warning(f"Job profession '{job_profession}' not found in database")
            return {
                "skills": [],
                "hot_technologies": [],
                "in_demand_skills": [],
                "tasks": []
            }
        
        return self.job_skill_mapping[job_profession]
    
    def analyze_skill_gap(self, 
                         resume_skills: List[str], 
                         target_job: str) -> Dict[str, Any]:
        """
        Perform comprehensive skill gap analysis
        
        Args:
            resume_skills: List of skills from resume
            target_job: Target job profession
            
        Returns:
            Detailed skill gap analysis results
        """
        # Match resume skills to master database
        matched_skills = self.extract_and_match_skills(resume_skills)
        matched_skill_names = [skill["matched_skill"] for skill in matched_skills]
        
        # Get required skills for target job
        job_requirements = self.get_job_required_skills(target_job)
        required_skills = [skill_info["skill"] for skill_info in job_requirements.get("skills", [])]
        hot_technologies = job_requirements.get("hot_technologies", [])
        in_demand_skills = job_requirements.get("in_demand_skills", [])
        
        # Calculate gaps
        missing_skills = [skill for skill in required_skills if skill not in matched_skill_names]
        present_skills = [skill for skill in required_skills if skill in matched_skill_names]
        
        # Calculate missing hot technologies and in-demand skills
        missing_hot_tech = [skill for skill in hot_technologies if skill not in matched_skill_names]
        missing_in_demand = [skill for skill in in_demand_skills if skill not in matched_skill_names]
        
        # Calculate proficiency scores
        total_required = len(required_skills)
        skills_present = len(present_skills)
        proficiency_score = (skills_present / max(total_required, 1)) * 100
        
        # Categorize skills by importance
        critical_missing = []
        important_missing = []
        nice_to_have_missing = []
        
        for skill in missing_skills:
            if skill in hot_technologies and skill in in_demand_skills:
                critical_missing.append(skill)
            elif skill in hot_technologies or skill in in_demand_skills:
                important_missing.append(skill)
            else:
                nice_to_have_missing.append(skill)
        
        return {
            "target_job": target_job,
            "proficiency_score": proficiency_score,
            "total_required_skills": total_required,
            "skills_present": skills_present,
            "matched_skills": matched_skills,
            "present_skills": present_skills,
            "missing_skills": missing_skills,
            "critical_missing": critical_missing,
            "important_missing": important_missing,
            "nice_to_have_missing": nice_to_have_missing,
            "missing_hot_technologies": missing_hot_tech,
            "missing_in_demand": missing_in_demand,
            "recommendations": self._generate_recommendations(
                critical_missing, important_missing, nice_to_have_missing
            ),
            "skill_categories": self._categorize_skills(present_skills, missing_skills)
        }
    
    def _generate_recommendations(self, 
                                 critical: List[str], 
                                 important: List[str], 
                                 nice_to_have: List[str]) -> Dict[str, Any]:
        """Generate learning recommendations based on missing skills"""
        recommendations = {
            "priority_order": [],
            "learning_path": [],
            "estimated_time": {}
        }
        
        # Priority order for learning
        if critical:
            recommendations["priority_order"].extend([
                {"skill": skill, "priority": "Critical", "reason": "High demand and trending"} 
                for skill in critical
            ])
        
        if important:
            recommendations["priority_order"].extend([
                {"skill": skill, "priority": "Important", "reason": "Industry demand or trending"} 
                for skill in important
            ])
        
        if nice_to_have:
            recommendations["priority_order"].extend([
                {"skill": skill, "priority": "Nice-to-have", "reason": "Complementary skill"} 
                for skill in nice_to_have[:5]  # Limit to top 5
            ])
        
        # Create learning path
        all_missing = critical + important + nice_to_have[:3]
        recommendations["learning_path"] = self._create_learning_path(all_missing)
        
        return recommendations
    
    def _create_learning_path(self, skills: List[str]) -> List[Dict]:
        """Create an optimized learning path for missing skills"""
        # This is a simplified version. In production, you'd want more sophisticated logic
        skill_categories = {
            "programming": ["Python", "Java", "JavaScript", "C++", "R"],
            "data_science": ["Machine Learning", "Deep Learning", "Statistics", "Data Analysis"],
            "web": ["HTML", "CSS", "React", "Angular", "Node.js"],
            "database": ["SQL", "MySQL", "PostgreSQL", "MongoDB"],
            "cloud": ["AWS", "Azure", "Google Cloud", "Docker", "Kubernetes"],
            "tools": ["Git", "Docker", "Jenkins", "Tableau"]
        }
        
        learning_path = []
        
        # Group skills by category for optimal learning order
        categorized_skills = {}
        for skill in skills:
            category = "other"
            for cat, cat_skills in skill_categories.items():
                if any(cat_skill.lower() in skill.lower() for cat_skill in cat_skills):
                    category = cat
                    break
            
            if category not in categorized_skills:
                categorized_skills[category] = []
            categorized_skills[category].append(skill)
        
        # Define learning order (foundational first)
        order = ["programming", "database", "tools", "data_science", "web", "cloud", "other"]
        
        for category in order:
            if category in categorized_skills:
                for skill in categorized_skills[category]:
                    learning_path.append({
                        "skill": skill,
                        "category": category,
                        "estimated_weeks": self._estimate_learning_time(skill, category),
                        "prerequisites": self._get_prerequisites(skill, category)
                    })
        
        return learning_path
    
    def _estimate_learning_time(self, skill: str, category: str) -> int:
        """Estimate learning time in weeks for a skill"""
        time_map = {
            "programming": 8,
            "data_science": 12,
            "web": 6,
            "database": 4,
            "cloud": 6,
            "tools": 2,
            "other": 4
        }
        return time_map.get(category, 4)
    
    def _get_prerequisites(self, skill: str, category: str) -> List[str]:
        """Get prerequisites for a skill"""
        prereq_map = {
            "Machine Learning": ["Python", "Statistics", "Mathematics"],
            "Deep Learning": ["Machine Learning", "Python", "TensorFlow"],
            "React": ["JavaScript", "HTML", "CSS"],
            "Node.js": ["JavaScript"],
            "Docker": ["Linux", "Command Line"],
            "Kubernetes": ["Docker", "Linux"]
        }
        return prereq_map.get(skill, [])
    
    def _categorize_skills(self, present: List[str], missing: List[str]) -> Dict[str, List[str]]:
        """Categorize skills into technical areas"""
        categories = {
            "Programming Languages": [],
            "Machine Learning/AI": [],
            "Web Technologies": [],
            "Databases": [],
            "Cloud & DevOps": [],
            "Data Analysis": [],
            "Other": []
        }
        
        all_skills = present + missing
        
        for skill in all_skills:
            skill_lower = skill.lower()
            
            if any(lang in skill_lower for lang in ['python', 'java', 'javascript', 'c++', 'r', 'sql']):
                categories["Programming Languages"].append(skill)
            elif any(ml in skill_lower for ml in ['machine learning', 'deep learning', 'tensorflow', 'scikit', 'neural']):
                categories["Machine Learning/AI"].append(skill)
            elif any(web in skill_lower for web in ['html', 'css', 'react', 'angular', 'node', 'express']):
                categories["Web Technologies"].append(skill)
            elif any(db in skill_lower for db in ['mysql', 'postgresql', 'mongodb', 'database', 'sql']):
                categories["Databases"].append(skill)
            elif any(cloud in skill_lower for cloud in ['aws', 'azure', 'cloud', 'docker', 'kubernetes']):
                categories["Cloud & DevOps"].append(skill)
            elif any(data in skill_lower for data in ['tableau', 'power bi', 'excel', 'analytics', 'statistics']):
                categories["Data Analysis"].append(skill)
            else:
                categories["Other"].append(skill)
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def create_skill_gap_visualization(self, analysis_result: Dict[str, Any]) -> Dict[str, str]:
        """
        Create various visualizations for skill gap analysis
        
        Args:
            analysis_result: Result from analyze_skill_gap method
            
        Returns:
            Dictionary with visualization data in JSON format
        """
        visualizations = {}
        
        # 1. Proficiency Score Gauge
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = analysis_result["proficiency_score"],
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Skill Proficiency Score"},
            delta = {'reference': 80},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "green"}],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90}}))
        
        visualizations["proficiency_gauge"] = fig_gauge.to_json()
        
        # 2. Skill Gap Bar Chart
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
        
        visualizations["skill_gap_bar"] = fig_bar.to_json()
        
        # 3. Skill Category Breakdown
        if analysis_result["skill_categories"]:
            categories = list(analysis_result["skill_categories"].keys())
            values = [len(skills) for skills in analysis_result["skill_categories"].values()]
            
            fig_pie = go.Figure(data=[go.Pie(labels=categories, values=values)])
            fig_pie.update_layout(title="Skills by Technical Category")
            
            visualizations["category_pie"] = fig_pie.to_json()
        
        # 4. Learning Path Timeline
        if analysis_result["recommendations"]["learning_path"]:
            skills = [item["skill"] for item in analysis_result["recommendations"]["learning_path"]]
            weeks = [item["estimated_weeks"] for item in analysis_result["recommendations"]["learning_path"]]
            
            # Calculate cumulative timeline
            cumulative_weeks = np.cumsum(weeks)
            
            fig_timeline = go.Figure()
            fig_timeline.add_trace(go.Scatter(
                x=cumulative_weeks,
                y=skills,
                mode='markers+lines',
                marker=dict(size=10, color='blue'),
                name='Learning Timeline'
            ))
            
            fig_timeline.update_layout(
                title="Recommended Learning Path Timeline",
                xaxis_title="Weeks",
                yaxis_title="Skills to Learn"
            )
            
            visualizations["learning_timeline"] = fig_timeline.to_json()
        
        return visualizations
    
    def get_available_jobs(self) -> List[str]:
        """Get list of available job professions"""
        return list(self.job_skill_mapping.keys())
    
    def batch_analyze_skills(self, skill_lists: List[List[str]], target_job: str) -> List[Dict]:
        """
        Analyze multiple skill sets in batch
        
        Args:
            skill_lists: List of skill lists to analyze
            target_job: Target job profession
            
        Returns:
            List of analysis results
        """
        results = []
        for skills in skill_lists:
            result = self.analyze_skill_gap(skills, target_job)
            results.append(result)
        
        return results

# Utility functions for integration with other components
def load_skills_from_resume_text(resume_text: str, skill_extractor) -> List[str]:
    """
    Extract skills from resume text using the trained spaCy model
    
    Args:
        resume_text: Raw resume text
        skill_extractor: Trained SkillExtractor instance
        
    Returns:
        List of extracted skill names
    """
    extracted_skills = skill_extractor.extract_skills(resume_text)
    return [skill["text"] for skill in extracted_skills]

def generate_course_recommendations(missing_skills: List[str], api_client) -> List[Dict]:
    """
    Generate course recommendations for missing skills
    
    Args:
        missing_skills: List of skills to learn
        api_client: Course API client instance
        
    Returns:
        List of recommended courses
    """
    recommendations = []
    
    for skill in missing_skills[:5]:  # Limit to top 5 skills
        try:
            courses = api_client.search_courses(skill)
            if courses:
                recommendations.append({
                    "skill": skill,
                    "courses": courses[:3]  # Top 3 courses per skill
                })
        except Exception as e:
            logger.error(f"Error getting courses for {skill}: {e}")
    
    return recommendations

if __name__ == "__main__":
    # Example usage
    skill_embeddings_path = "../../data/processed/skill_embeddings.json"
    job_mapping_path = "../../data/processed/job_skill_mapping.json"
    
    analyzer = SkillGapAnalyzer(skill_embeddings_path, job_mapping_path)
    
    # Example analysis
    resume_skills = ["Python", "machine learning", "SQL", "data analysis"]
    target_job = "Data Science"
    
    result = analyzer.analyze_skill_gap(resume_skills, target_job)
    visualizations = analyzer.create_skill_gap_visualization(result)
    
    print(f"Proficiency Score: {result['proficiency_score']:.1f}%")
    print(f"Missing Critical Skills: {result['critical_missing']}")
    print(f"Learning Recommendations: {len(result['recommendations']['learning_path'])} skills")
