-- Import Actual Data from CSV Files
-- This script imports real skills and job professions from the provided datasets
-- Run this script after creating the schema

USE skill_gap_analyzer;

-- First, let's create temporary tables to load CSV data
CREATE TEMPORARY TABLE temp_skills_data (
    job_profession VARCHAR(255),
    skills VARCHAR(255),
    commodity_code VARCHAR(50),
    tasks_wanted_to_learn TEXT,
    hot_technology CHAR(1),
    in_demand CHAR(1)
);

-- Load the skills database CSV data
-- Note: You'll need to adjust the file path to match your system
-- For Windows, use forward slashes or double backslashes
LOAD DATA INFILE 'D:/ML PROJECT/skill-gap-analyzer/data/raw/skills_database.csv'
INTO TABLE temp_skills_data
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS
(job_profession, skills, commodity_code, tasks_wanted_to_learn, hot_technology, in_demand);

-- Insert unique skills from the dataset
INSERT IGNORE INTO skills (id, name, description, category, is_hot_technology, is_in_demand)
SELECT 
    UUID() as id,
    TRIM(skills) as name,
    CONCAT('Skill used in ', job_profession, ' roles') as description,
    CASE 
        WHEN LOWER(skills) LIKE '%python%' OR LOWER(skills) LIKE '%java%' OR LOWER(skills) LIKE '%javascript%' OR LOWER(skills) LIKE '%sql%' 
            THEN 'Programming Languages'
        WHEN LOWER(skills) LIKE '%machine learning%' OR LOWER(skills) LIKE '%deep learning%' OR LOWER(skills) LIKE '%tensorflow%' OR LOWER(skills) LIKE '%scikit%'
            THEN 'Machine Learning/AI'
        WHEN LOWER(skills) LIKE '%html%' OR LOWER(skills) LIKE '%css%' OR LOWER(skills) LIKE '%react%' OR LOWER(skills) LIKE '%angular%'
            THEN 'Web Technologies'
        WHEN LOWER(skills) LIKE '%mysql%' OR LOWER(skills) LIKE '%postgresql%' OR LOWER(skills) LIKE '%mongodb%' OR LOWER(skills) LIKE '%database%'
            THEN 'Database'
        WHEN LOWER(skills) LIKE '%aws%' OR LOWER(skills) LIKE '%azure%' OR LOWER(skills) LIKE '%cloud%' OR LOWER(skills) LIKE '%docker%'
            THEN 'Cloud & DevOps'
        WHEN LOWER(skills) LIKE '%tableau%' OR LOWER(skills) LIKE '%power bi%' OR LOWER(skills) LIKE '%excel%' OR LOWER(skills) LIKE '%analytics%'
            THEN 'Data Analysis'
        ELSE 'Other'
    END as category,
    CASE WHEN hot_technology = 'Y' THEN TRUE ELSE FALSE END as is_hot_technology,
    CASE WHEN in_demand = 'Y' THEN TRUE ELSE FALSE END as is_in_demand
FROM temp_skills_data
WHERE TRIM(skills) != '' AND TRIM(skills) IS NOT NULL
GROUP BY TRIM(skills);

-- Insert unique job professions
INSERT IGNORE INTO job_professions (id, name, description, category)
SELECT 
    UUID() as id,
    TRIM(job_profession) as name,
    CONCAT('Professional role requiring various technical and soft skills') as description,
    CASE 
        WHEN LOWER(job_profession) LIKE '%data%' OR LOWER(job_profession) LIKE '%analyst%' OR LOWER(job_profession) LIKE '%scientist%'
            THEN 'Data & Analytics'
        WHEN LOWER(job_profession) LIKE '%software%' OR LOWER(job_profession) LIKE '%developer%' OR LOWER(job_profession) LIKE '%engineer%'
            THEN 'Software Development'
        WHEN LOWER(job_profession) LIKE '%manager%' OR LOWER(job_profession) LIKE '%director%' OR LOWER(job_profession) LIKE '%executive%'
            THEN 'Management'
        WHEN LOWER(job_profession) LIKE '%marketing%' OR LOWER(job_profession) LIKE '%sales%'
            THEN 'Marketing & Sales'
        ELSE 'Other'
    END as category
FROM temp_skills_data
WHERE TRIM(job_profession) != '' AND TRIM(job_profession) IS NOT NULL
GROUP BY TRIM(job_profession);

-- Create job-skill requirements mapping
INSERT INTO job_skill_requirements (id, job_id, skill_id, importance_level, task_description)
SELECT 
    UUID() as id,
    jp.id as job_id,
    s.id as skill_id,
    CASE 
        WHEN tsd.hot_technology = 'Y' AND tsd.in_demand = 'Y' THEN 'Critical'
        WHEN tsd.hot_technology = 'Y' OR tsd.in_demand = 'Y' THEN 'Important'
        ELSE 'Nice-to-have'
    END as importance_level,
    TRIM(tsd.tasks_wanted_to_learn) as task_description
FROM temp_skills_data tsd
JOIN job_professions jp ON TRIM(jp.name) = TRIM(tsd.job_profession)
JOIN skills s ON TRIM(s.name) = TRIM(tsd.skills)
WHERE TRIM(tsd.skills) != '' AND TRIM(tsd.job_profession) != '';

-- Clean up temporary table
DROP TEMPORARY TABLE temp_skills_data;

-- Add some sample users for testing (you can remove this if not needed)
INSERT INTO users (id, email, full_name, hashed_password, is_active) VALUES
(UUID(), 'admin@skillgap.com', 'System Administrator', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj.LzjhKI6F6', TRUE),
(UUID(), 'demo@skillgap.com', 'Demo User', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj.LzjhKI6F6', TRUE);

-- Display import statistics
SELECT 'Import Statistics:' as info;

SELECT 
    'Skills Imported' as metric,
    COUNT(*) as count,
    COUNT(CASE WHEN is_hot_technology = TRUE THEN 1 END) as hot_technologies,
    COUNT(CASE WHEN is_in_demand = TRUE THEN 1 END) as in_demand_skills
FROM skills;

SELECT 
    'Job Professions Imported' as metric,
    COUNT(*) as count
FROM job_professions;

SELECT 
    'Job-Skill Mappings Created' as metric,
    COUNT(*) as count,
    COUNT(CASE WHEN importance_level = 'Critical' THEN 1 END) as critical,
    COUNT(CASE WHEN importance_level = 'Important' THEN 1 END) as important,
    COUNT(CASE WHEN importance_level = 'Nice-to-have' THEN 1 END) as nice_to_have
FROM job_skill_requirements;

-- Show sample of imported data
SELECT 'Sample Skills by Category:' as info;
SELECT 
    category,
    COUNT(*) as skill_count,
    COUNT(CASE WHEN is_hot_technology = TRUE THEN 1 END) as hot_tech_count
FROM skills 
GROUP BY category 
ORDER BY skill_count DESC;

SELECT 'Sample Job Professions by Category:' as info;
SELECT 
    category,
    COUNT(*) as job_count
FROM job_professions 
GROUP BY category 
ORDER BY job_count DESC;

-- Show top skills by demand
SELECT 'Top 20 Most In-Demand Skills:' as info;
SELECT 
    s.name as skill_name,
    s.category,
    COUNT(jsr.job_id) as required_by_jobs,
    s.is_hot_technology,
    s.is_in_demand
FROM skills s
LEFT JOIN job_skill_requirements jsr ON s.id = jsr.skill_id
WHERE s.is_in_demand = TRUE
GROUP BY s.id, s.name, s.category, s.is_hot_technology, s.is_in_demand
ORDER BY required_by_jobs DESC, s.name
LIMIT 20;

-- Show jobs with most skill requirements
SELECT 'Jobs with Most Skill Requirements:' as info;
SELECT 
    jp.name as job_name,
    jp.category,
    COUNT(jsr.skill_id) as required_skills_count,
    COUNT(CASE WHEN jsr.importance_level = 'Critical' THEN 1 END) as critical_skills,
    COUNT(CASE WHEN jsr.importance_level = 'Important' THEN 1 END) as important_skills
FROM job_professions jp
LEFT JOIN job_skill_requirements jsr ON jp.id = jsr.job_id
GROUP BY jp.id, jp.name, jp.category
ORDER BY required_skills_count DESC
LIMIT 15;
