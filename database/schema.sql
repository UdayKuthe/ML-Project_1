-- Skill Gap Analyzer Database Schema
-- MySQL Database Creation Script
-- Run this script in MySQL shell or MySQL Workbench

-- Create database
CREATE DATABASE IF NOT EXISTS skill_gap_analyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE skill_gap_analyzer;

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS course_recommendations;
DROP TABLE IF EXISTS skill_trends;
DROP TABLE IF EXISTS skill_analyses;
DROP TABLE IF EXISTS resume_skills;
DROP TABLE IF EXISTS job_skill_requirements;
DROP TABLE IF EXISTS resumes;
DROP TABLE IF EXISTS skills;
DROP TABLE IF EXISTS job_professions;
DROP TABLE IF EXISTS users;

-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_active (is_active)
);

-- Job professions table
CREATE TABLE job_professions (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_category (category)
);

-- Skills master table
CREATE TABLE skills (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100),
    is_hot_technology BOOLEAN DEFAULT FALSE,
    is_in_demand BOOLEAN DEFAULT FALSE,
    embedding_vector JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_category (category),
    INDEX idx_hot_tech (is_hot_technology),
    INDEX idx_in_demand (is_in_demand)
);

-- Job-Skill requirements mapping table
CREATE TABLE job_skill_requirements (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    job_id VARCHAR(36) NOT NULL,
    skill_id VARCHAR(36) NOT NULL,
    importance_level ENUM('Critical', 'Important', 'Nice-to-have') DEFAULT 'Important',
    task_description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES job_professions(id) ON DELETE CASCADE,
    FOREIGN KEY (skill_id) REFERENCES skills(id) ON DELETE CASCADE,
    UNIQUE KEY unique_job_skill (job_id, skill_id),
    INDEX idx_job_id (job_id),
    INDEX idx_skill_id (skill_id),
    INDEX idx_importance (importance_level)
);

-- Resumes table
CREATE TABLE resumes (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id VARCHAR(36) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500),
    raw_text LONGTEXT,
    file_size INT UNSIGNED,
    mime_type VARCHAR(100),
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_processed (processed),
    INDEX idx_created_at (created_at)
);

-- Resume skills extracted table
CREATE TABLE resume_skills (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    resume_id VARCHAR(36) NOT NULL,
    skill_id VARCHAR(36) NOT NULL,
    original_text VARCHAR(255),
    confidence_score DECIMAL(4,3),
    match_type ENUM('exact', 'semantic', 'fuzzy') DEFAULT 'exact',
    position_start INT UNSIGNED,
    position_end INT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (resume_id) REFERENCES resumes(id) ON DELETE CASCADE,
    FOREIGN KEY (skill_id) REFERENCES skills(id) ON DELETE CASCADE,
    INDEX idx_resume_id (resume_id),
    INDEX idx_skill_id (skill_id),
    INDEX idx_confidence (confidence_score),
    INDEX idx_match_type (match_type)
);

-- Skill analyses table
CREATE TABLE skill_analyses (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id VARCHAR(36) NOT NULL,
    resume_id VARCHAR(36) NOT NULL,
    target_job_id VARCHAR(36) NOT NULL,
    proficiency_score DECIMAL(5,2),
    total_required_skills INT UNSIGNED,
    skills_present INT UNSIGNED,
    analysis_results JSON,
    visualizations JSON,
    analysis_version VARCHAR(20) DEFAULT '1.0',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (resume_id) REFERENCES resumes(id) ON DELETE CASCADE,
    FOREIGN KEY (target_job_id) REFERENCES job_professions(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_resume_id (resume_id),
    INDEX idx_target_job_id (target_job_id),
    INDEX idx_proficiency (proficiency_score),
    INDEX idx_created_at (created_at)
);

-- Course recommendations table
CREATE TABLE course_recommendations (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    analysis_id VARCHAR(36) NOT NULL,
    skill_name VARCHAR(255) NOT NULL,
    course_title VARCHAR(500),
    course_provider VARCHAR(255),
    course_url VARCHAR(1000),
    course_description TEXT,
    estimated_duration VARCHAR(100),
    difficulty_level ENUM('Beginner', 'Intermediate', 'Advanced'),
    rating DECIMAL(3,2),
    price VARCHAR(100),
    recommendation_score DECIMAL(4,3),
    priority ENUM('Critical', 'Important', 'Nice-to-have') DEFAULT 'Important',
    external_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES skill_analyses(id) ON DELETE CASCADE,
    INDEX idx_analysis_id (analysis_id),
    INDEX idx_skill_name (skill_name),
    INDEX idx_priority (priority),
    INDEX idx_recommendation_score (recommendation_score)
);

-- Skill trends table for time series analysis
CREATE TABLE skill_trends (
    id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
    skill_id VARCHAR(36) NOT NULL,
    date_period VARCHAR(7) NOT NULL, -- YYYY-MM format
    demand_score DECIMAL(5,2),
    job_postings_count INT UNSIGNED DEFAULT 0,
    salary_trend DECIMAL(10,2),
    growth_rate DECIMAL(5,2),
    data_source VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (skill_id) REFERENCES skills(id) ON DELETE CASCADE,
    UNIQUE KEY unique_skill_period (skill_id, date_period),
    INDEX idx_skill_id (skill_id),
    INDEX idx_date_period (date_period),
    INDEX idx_demand_score (demand_score),
    INDEX idx_data_source (data_source)
);

-- Performance optimization indexes
CREATE INDEX idx_resume_skills_composite ON resume_skills(resume_id, confidence_score DESC);
CREATE INDEX idx_skill_analyses_composite ON skill_analyses(user_id, created_at DESC);
CREATE INDEX idx_course_recommendations_composite ON course_recommendations(analysis_id, recommendation_score DESC);

SHOW TABLES;
