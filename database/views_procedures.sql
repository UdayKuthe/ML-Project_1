-- Views and Stored Procedures for Skill Gap Analyzer
-- Run this script after creating the main schema

USE skill_gap_analyzer;

-- Create views for common queries
CREATE VIEW v_user_analyses AS
SELECT 
    sa.id,
    sa.user_id,
    u.full_name as user_name,
    u.email,
    sa.proficiency_score,
    jp.name as target_job_name,
    jp.category as job_category,
    sa.total_required_skills,
    sa.skills_present,
    sa.created_at,
    r.filename as resume_filename
FROM skill_analyses sa
JOIN users u ON sa.user_id = u.id
JOIN job_professions jp ON sa.target_job_id = jp.id
JOIN resumes r ON sa.resume_id = r.id
WHERE u.is_active = TRUE;

CREATE VIEW v_skill_demand_summary AS
SELECT 
    s.id,
    s.name,
    s.category,
    s.is_hot_technology,
    s.is_in_demand,
    COUNT(DISTINCT jsr.job_id) as required_by_jobs,
    AVG(st.demand_score) as avg_demand_score,
    COUNT(DISTINCT rs.resume_id) as found_in_resumes,
    COUNT(DISTINCT cr.id) as recommended_courses
FROM skills s
LEFT JOIN job_skill_requirements jsr ON s.id = jsr.skill_id
LEFT JOIN skill_trends st ON s.id = st.skill_id
LEFT JOIN resume_skills rs ON s.id = rs.skill_id
LEFT JOIN course_recommendations cr ON s.name = cr.skill_name
GROUP BY s.id, s.name, s.category, s.is_hot_technology, s.is_in_demand;

CREATE VIEW v_job_skill_matrix AS
SELECT 
    jp.id as job_id,
    jp.name as job_name,
    jp.category as job_category,
    s.id as skill_id,
    s.name as skill_name,
    s.category as skill_category,
    jsr.importance_level,
    jsr.task_description,
    s.is_hot_technology,
    s.is_in_demand
FROM job_professions jp
JOIN job_skill_requirements jsr ON jp.id = jsr.job_id
JOIN skills s ON jsr.skill_id = s.id
ORDER BY jp.name, jsr.importance_level, s.name;

CREATE VIEW v_resume_analysis_summary AS
SELECT 
    r.id as resume_id,
    r.user_id,
    u.full_name as user_name,
    r.filename,
    COUNT(DISTINCT rs.skill_id) as total_skills_found,
    AVG(rs.confidence_score) as avg_confidence,
    COUNT(DISTINCT sa.id) as analysis_count,
    MAX(sa.proficiency_score) as best_proficiency_score,
    r.created_at as resume_uploaded_at
FROM resumes r
JOIN users u ON r.user_id = u.id
LEFT JOIN resume_skills rs ON r.id = rs.resume_id
LEFT JOIN skill_analyses sa ON r.id = sa.resume_id
WHERE r.processed = TRUE
GROUP BY r.id, r.user_id, u.full_name, r.filename, r.created_at;

CREATE VIEW v_trending_skills AS
SELECT 
    s.id,
    s.name,
    s.category,
    AVG(st.demand_score) as avg_demand,
    AVG(st.growth_rate) as avg_growth_rate,
    COUNT(st.id) as data_points,
    MAX(st.date_period) as latest_period
FROM skills s
JOIN skill_trends st ON s.id = st.skill_id
WHERE st.date_period >= DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 12 MONTH), '%Y-%m')
GROUP BY s.id, s.name, s.category
HAVING COUNT(st.id) >= 6  -- At least 6 months of data
ORDER BY avg_growth_rate DESC, avg_demand DESC;

-- Create stored procedures for common operations
DELIMITER //

CREATE PROCEDURE GetUserSkillAnalyses(IN p_user_id VARCHAR(36))
BEGIN
    SELECT 
        sa.*,
        jp.name as job_name,
        jp.category as job_category,
        r.filename as resume_filename
    FROM skill_analyses sa
    JOIN job_professions jp ON sa.target_job_id = jp.id
    JOIN resumes r ON sa.resume_id = r.id
    WHERE sa.user_id = p_user_id
    ORDER BY sa.created_at DESC;
END//

CREATE PROCEDURE GetJobRequiredSkills(IN p_job_id VARCHAR(36))
BEGIN
    SELECT 
        s.*,
        jsr.importance_level,
        jsr.task_description
    FROM skills s
    JOIN job_skill_requirements jsr ON s.id = jsr.skill_id
    WHERE jsr.job_id = p_job_id
    ORDER BY 
        CASE jsr.importance_level 
            WHEN 'Critical' THEN 1
            WHEN 'Important' THEN 2
            WHEN 'Nice-to-have' THEN 3
        END,
        s.name;
END//

CREATE PROCEDURE GetSkillTrends(IN p_skill_id VARCHAR(36), IN p_months_back INT)
BEGIN
    SELECT 
        st.*,
        s.name as skill_name
    FROM skill_trends st
    JOIN skills s ON st.skill_id = s.id
    WHERE st.skill_id = p_skill_id
    AND STR_TO_DATE(CONCAT(st.date_period, '-01'), '%Y-%m-%d') >= DATE_SUB(CURDATE(), INTERVAL p_months_back MONTH)
    ORDER BY st.date_period DESC;
END//

CREATE PROCEDURE GetResumeSkills(IN p_resume_id VARCHAR(36))
BEGIN
    SELECT 
        rs.*,
        s.name as skill_name,
        s.category as skill_category,
        s.is_hot_technology,
        s.is_in_demand
    FROM resume_skills rs
    JOIN skills s ON rs.skill_id = s.id
    WHERE rs.resume_id = p_resume_id
    ORDER BY rs.confidence_score DESC;
END//

CREATE PROCEDURE GetCourseRecommendations(IN p_analysis_id VARCHAR(36))
BEGIN
    SELECT 
        cr.*
    FROM course_recommendations cr
    WHERE cr.analysis_id = p_analysis_id
    ORDER BY 
        CASE cr.priority 
            WHEN 'Critical' THEN 1
            WHEN 'Important' THEN 2
            WHEN 'Nice-to-have' THEN 3
        END,
        cr.recommendation_score DESC;
END//

CREATE PROCEDURE SearchJobs(IN p_search_term VARCHAR(255))
BEGIN
    SELECT 
        jp.*,
        COUNT(jsr.skill_id) as required_skills_count
    FROM job_professions jp
    LEFT JOIN job_skill_requirements jsr ON jp.id = jsr.job_id
    WHERE jp.name LIKE CONCAT('%', p_search_term, '%')
       OR jp.description LIKE CONCAT('%', p_search_term, '%')
       OR jp.category LIKE CONCAT('%', p_search_term, '%')
    GROUP BY jp.id, jp.name, jp.description, jp.category, jp.created_at, jp.updated_at
    ORDER BY jp.name;
END//

CREATE PROCEDURE SearchSkills(IN p_search_term VARCHAR(255))
BEGIN
    SELECT 
        s.*,
        COUNT(DISTINCT jsr.job_id) as required_by_jobs,
        COUNT(DISTINCT rs.resume_id) as found_in_resumes
    FROM skills s
    LEFT JOIN job_skill_requirements jsr ON s.id = jsr.skill_id
    LEFT JOIN resume_skills rs ON s.id = rs.skill_id
    WHERE s.name LIKE CONCAT('%', p_search_term, '%')
       OR s.description LIKE CONCAT('%', p_search_term, '%')
       OR s.category LIKE CONCAT('%', p_search_term, '%')
    GROUP BY s.id, s.name, s.description, s.category, s.is_hot_technology, s.is_in_demand, s.created_at, s.updated_at
    ORDER BY s.name;
END//

CREATE PROCEDURE GetUserDashboardData(IN p_user_id VARCHAR(36))
BEGIN
    -- Get user's recent analyses
    SELECT 
        'recent_analyses' as data_type,
        COUNT(*) as count
    FROM skill_analyses sa
    WHERE sa.user_id = p_user_id
    AND sa.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    
    UNION ALL
    
    -- Get user's average proficiency score
    SELECT 
        'avg_proficiency' as data_type,
        ROUND(AVG(sa.proficiency_score), 2) as count
    FROM skill_analyses sa
    WHERE sa.user_id = p_user_id
    
    UNION ALL
    
    -- Get total resumes uploaded
    SELECT 
        'total_resumes' as data_type,
        COUNT(*) as count
    FROM resumes r
    WHERE r.user_id = p_user_id;
END//

DELIMITER ;

-- Create triggers for automatic data maintenance
DELIMITER //

CREATE TRIGGER after_analysis_insert
    AFTER INSERT ON skill_analyses
    FOR EACH ROW
BEGIN
    -- Update user's last activity (you might want to add a last_activity column to users table)
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.user_id;
END//

CREATE TRIGGER after_resume_upload
    AFTER INSERT ON resumes
    FOR EACH ROW
BEGIN
    -- Update user's last activity
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.user_id;
END//

CREATE TRIGGER before_skill_delete
    BEFORE DELETE ON skills
    FOR EACH ROW
BEGIN
    -- Clean up related data before deleting a skill
    DELETE FROM skill_trends WHERE skill_id = OLD.id;
END//

DELIMITER ;

-- Create indexes for better performance on views
CREATE INDEX idx_skill_analyses_user_created ON skill_analyses(user_id, created_at DESC);
CREATE INDEX idx_resume_skills_resume_confidence ON resume_skills(resume_id, confidence_score DESC);
CREATE INDEX idx_job_skill_req_job_importance ON job_skill_requirements(job_id, importance_level);
CREATE INDEX idx_skill_trends_period ON skill_trends(date_period DESC);

-- Show created views and procedures
SHOW FULL TABLES WHERE Table_type = 'VIEW';
SHOW PROCEDURE STATUS WHERE Db = 'skill_gap_analyzer';
