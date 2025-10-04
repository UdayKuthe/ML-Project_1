"""
Course recommendation engine with external API integration
"""

import requests
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import quote
import json
import time
from config import Config

logger = logging.getLogger(__name__)

class CourseRecommendationEngine:
    """
    Course recommendation engine that integrates with multiple course platforms
    """
    
    def __init__(self):
        self.course_api_key = Config.COURSE_API_KEY
        self.course_api_base_url = Config.COURSE_API_BASE_URL
        self.timeout = 10  # seconds
        
    def recommend_courses_for_skills(self, missing_skills: List[str], max_courses_per_skill: int = 3) -> List[Dict[str, Any]]:
        """
        Get course recommendations for a list of missing skills
        
        Args:
            missing_skills: List of skill names that need to be learned
            max_courses_per_skill: Maximum number of courses to recommend per skill
            
        Returns:
            List of course recommendations
        """
        recommendations = []
        
        for skill in missing_skills[:10]:  # Limit to top 10 skills to avoid API rate limits
            try:
                courses = self.search_courses_for_skill(skill, max_courses_per_skill)
                if courses:
                    recommendations.extend(courses)
                    
                # Add small delay to respect API rate limits
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error getting courses for skill '{skill}': {e}")
                # Add fallback/dummy course for this skill
                recommendations.append(self.create_fallback_recommendation(skill))
        
        return recommendations
    
    def search_courses_for_skill(self, skill: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """
        Search for courses related to a specific skill
        
        Args:
            skill: Name of the skill
            max_results: Maximum number of courses to return
            
        Returns:
            List of course recommendations for the skill
        """
        courses = []
        
        # Try multiple course platforms
        platforms = [
            self.search_coursera_courses,
            self.search_udemy_courses,
            self.search_edx_courses,
            self.search_generic_courses  # Fallback
        ]
        
        for search_func in platforms:
            try:
                platform_courses = search_func(skill, max_results)
                courses.extend(platform_courses)
                
                # Stop if we have enough courses
                if len(courses) >= max_results:
                    break
                    
            except Exception as e:
                logger.warning(f"Error searching courses from {search_func.__name__}: {e}")
                continue
        
        # Limit results and add skill name to each course
        limited_courses = courses[:max_results]
        for course in limited_courses:
            course['skill_name'] = skill
            
        return limited_courses
    
    def search_coursera_courses(self, skill: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """Search Coursera for courses (requires API key)"""
        if not self.course_api_key:
            raise ValueError("Coursera API key not configured")
        
        try:
            # Coursera API endpoint (this is a placeholder - adjust based on actual API)
            url = f"{self.course_api_base_url}/courses"
            params = {
                'q': skill,
                'limit': max_results,
                'fields': 'name,description,instructors,workload,photoUrl'
            }
            headers = {
                'Authorization': f'Bearer {self.course_api_key}'
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            courses = []
            
            for course_data in data.get('elements', []):
                course = {
                    'course_title': course_data.get('name', 'Unknown Course'),
                    'course_provider': 'Coursera',
                    'course_url': f"https://coursera.org/learn/{course_data.get('slug', '')}",
                    'course_description': course_data.get('description', '')[:500],
                    'estimated_duration': self.parse_workload(course_data.get('workload')),
                    'difficulty_level': 'Intermediate',  # Default
                    'rating': course_data.get('averageRating', 4.0),
                    'price': 'Varies',
                    'recommendation_score': self.calculate_relevance_score(skill, course_data.get('name', '')),
                    'priority': 'Important',
                    'external_id': course_data.get('id')
                }
                courses.append(course)
            
            return courses
            
        except Exception as e:
            logger.error(f"Error searching Coursera: {e}")
            return []
    
    def search_udemy_courses(self, skill: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """Search Udemy for courses (using public API or scraping)"""
        try:
            # This is a placeholder - Udemy has affiliate API
            # For demo purposes, we'll create realistic fake data
            return self.create_sample_udemy_courses(skill, max_results)
            
        except Exception as e:
            logger.error(f"Error searching Udemy: {e}")
            return []
    
    def search_edx_courses(self, skill: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """Search edX for courses"""
        try:
            # This is a placeholder - edX has an API
            # For demo purposes, we'll create realistic fake data
            return self.create_sample_edx_courses(skill, max_results)
            
        except Exception as e:
            logger.error(f"Error searching edX: {e}")
            return []
    
    def search_generic_courses(self, skill: str, max_results: int = 3) -> List[Dict[str, Any]]:
        """Generic course search (fallback)"""
        return self.create_generic_course_recommendations(skill, max_results)
    
    def create_sample_udemy_courses(self, skill: str, max_results: int) -> List[Dict[str, Any]]:
        """Create sample Udemy course recommendations"""
        templates = [
            {
                'course_title': f'Complete {skill} Masterclass',
                'course_description': f'Learn {skill} from beginner to advanced level with hands-on projects',
                'estimated_duration': '40 hours',
                'difficulty_level': 'Beginner',
                'rating': 4.5,
                'price': '$89.99'
            },
            {
                'course_title': f'{skill} for Professionals',
                'course_description': f'Advanced {skill} techniques for working professionals',
                'estimated_duration': '25 hours',
                'difficulty_level': 'Intermediate',
                'rating': 4.3,
                'price': '$74.99'
            },
            {
                'course_title': f'Hands-on {skill} Projects',
                'course_description': f'Build real-world projects using {skill}',
                'estimated_duration': '30 hours',
                'difficulty_level': 'Advanced',
                'rating': 4.7,
                'price': '$99.99'
            }
        ]
        
        courses = []
        for i, template in enumerate(templates[:max_results]):
            course = template.copy()
            course.update({
                'course_provider': 'Udemy',
                'course_url': f'https://udemy.com/course/{skill.lower().replace(" ", "-")}-{i+1}',
                'recommendation_score': 0.85 - (i * 0.1),
                'priority': 'Important' if i == 0 else 'Nice-to-have',
                'external_id': f'udemy-{skill.lower()}-{i+1}'
            })
            courses.append(course)
        
        return courses
    
    def create_sample_edx_courses(self, skill: str, max_results: int) -> List[Dict[str, Any]]:
        """Create sample edX course recommendations"""
        templates = [
            {
                'course_title': f'Introduction to {skill}',
                'course_description': f'University-level course covering fundamentals of {skill}',
                'estimated_duration': '8 weeks',
                'difficulty_level': 'Beginner',
                'rating': 4.2,
                'price': 'Free (Certificate: $99)'
            },
            {
                'course_title': f'{skill} Specialization',
                'course_description': f'Professional certificate program in {skill}',
                'estimated_duration': '12 weeks',
                'difficulty_level': 'Intermediate',
                'rating': 4.4,
                'price': 'Free (Certificate: $199)'
            }
        ]
        
        courses = []
        for i, template in enumerate(templates[:max_results]):
            course = template.copy()
            course.update({
                'course_provider': 'edX',
                'course_url': f'https://edx.org/course/{skill.lower().replace(" ", "-")}-{i+1}',
                'recommendation_score': 0.80 - (i * 0.1),
                'priority': 'Important',
                'external_id': f'edx-{skill.lower()}-{i+1}'
            })
            courses.append(course)
        
        return courses
    
    def create_generic_course_recommendations(self, skill: str, max_results: int) -> List[Dict[str, Any]]:
        """Create generic course recommendations as fallback"""
        recommendations = [
            {
                'course_title': f'Learn {skill} - Complete Guide',
                'course_provider': 'Online Learning Platform',
                'course_url': f'https://example.com/courses/{skill.lower().replace(" ", "-")}',
                'course_description': f'Comprehensive course covering all aspects of {skill}',
                'estimated_duration': '6-8 weeks',
                'difficulty_level': 'Beginner',
                'rating': 4.0,
                'price': 'Varies',
                'recommendation_score': 0.75,
                'priority': 'Important',
                'external_id': f'generic-{skill.lower()}'
            }
        ]
        
        return recommendations[:max_results]
    
    def create_fallback_recommendation(self, skill: str) -> Dict[str, Any]:
        """Create a single fallback recommendation for a skill"""
        return {
            'skill_name': skill,
            'course_title': f'Learn {skill}',
            'course_provider': 'Various Platforms',
            'course_url': f'https://www.google.com/search?q=learn+{quote(skill)}+online+course',
            'course_description': f'Search for online courses and tutorials to learn {skill}',
            'estimated_duration': 'Varies',
            'difficulty_level': 'Beginner',
            'rating': None,
            'price': 'Varies',
            'recommendation_score': 0.5,
            'priority': 'Nice-to-have',
            'external_id': f'fallback-{skill.lower()}'
        }
    
    def calculate_relevance_score(self, skill: str, course_title: str) -> float:
        """Calculate how relevant a course is to a skill"""
        skill_words = set(skill.lower().split())
        title_words = set(course_title.lower().split())
        
        # Simple word overlap scoring
        overlap = len(skill_words.intersection(title_words))
        total_words = len(skill_words.union(title_words))
        
        if total_words == 0:
            return 0.5
        
        base_score = overlap / total_words
        
        # Boost score if skill name appears exactly in title
        if skill.lower() in course_title.lower():
            base_score += 0.3
        
        return min(base_score, 1.0)
    
    def parse_workload(self, workload_str: Optional[str]) -> str:
        """Parse workload string into readable format"""
        if not workload_str:
            return 'Not specified'
        
        # Simple parsing - adjust based on actual API response format
        if 'hour' in workload_str.lower():
            return workload_str
        elif 'week' in workload_str.lower():
            return workload_str
        else:
            return f'{workload_str} hours'
    
    def categorize_priority(self, skill: str, missing_skills: List[str]) -> str:
        """Categorize the priority of learning a skill"""
        skill_index = missing_skills.index(skill) if skill in missing_skills else len(missing_skills)
        
        if skill_index < 3:
            return 'Critical'
        elif skill_index < 7:
            return 'Important'
        else:
            return 'Nice-to-have'

# Global instance
course_recommender = CourseRecommendationEngine()

# Utility functions
def get_course_recommendations(missing_skills: List[str]) -> List[Dict[str, Any]]:
    """Get course recommendations for missing skills"""
    return course_recommender.recommend_courses_for_skills(missing_skills)

def search_courses_for_skill(skill: str, max_results: int = 3) -> List[Dict[str, Any]]:
    """Search for courses for a specific skill"""
    return course_recommender.search_courses_for_skill(skill, max_results)
