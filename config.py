import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database Configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'mysql://user:password@localhost/skill_gap_analyzer')
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    
    # Model Paths
    SPACY_MODEL_PATH = os.getenv('SPACY_MODEL_PATH', './backend/trained_models/skill_extraction_model')
    SBERT_MODEL_NAME = os.getenv('SBERT_MODEL_NAME', 'all-MiniLM-L6-v2')
    
    # File Upload Settings
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', './backend/data/uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
    
    # API Settings
    API_HOST = os.getenv('API_HOST', '0.0.0.0')
    API_PORT = int(os.getenv('API_PORT', 8000))
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Course Recommendation API
    COURSE_API_KEY = os.getenv('COURSE_API_KEY', '')
    COURSE_API_BASE_URL = os.getenv('COURSE_API_BASE_URL', 'https://api.coursera.org/api/courses.v1')
    
    # Skill Similarity Threshold
    SKILL_SIMILARITY_THRESHOLD = float(os.getenv('SKILL_SIMILARITY_THRESHOLD', '0.7'))
    
    # Data Paths
    RAW_DATA_PATH = './data/raw/'
    PROCESSED_DATA_PATH = './data/processed/'
    TRAINING_DATA_PATH = './data/training/'
    
    # Model Training Settings
    TRAINING_EPOCHS = int(os.getenv('TRAINING_EPOCHS', '10'))
    BATCH_SIZE = int(os.getenv('BATCH_SIZE', '32'))
    LEARNING_RATE = float(os.getenv('LEARNING_RATE', '0.001'))

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    
class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = 'sqlite:///test.db'

config_dict = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}
