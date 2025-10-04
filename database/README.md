# Database Setup Guide

This guide explains how to set up the MySQL database for the Skill Gap Analyzer project.

## Prerequisites

1. **MySQL Server** (version 8.0 or higher recommended)
2. **MySQL Workbench** or **MySQL Command Line Client**
3. **Python 3.8+** (for alternative data import method)

## Database Setup Steps

### Step 1: Create Database Schema

1. Open MySQL Workbench or connect to MySQL command line
2. Run the schema creation script:

```bash
mysql -u root -p < database/schema.sql
```

Or execute the contents of `schema.sql` in MySQL Workbench.

### Step 2: Create Views and Stored Procedures

Run the views and procedures script:

```bash
mysql -u root -p < database/views_procedures.sql
```

### Step 3: Import Actual Data

You have two options for importing the real skill and job profession data:

#### Option A: Using Python Script (Recommended)

1. Install required Python packages:
```bash
pip install pandas mysql-connector-python
```

2. Update database credentials in `scripts/import_data.py`:
```python
db_config = {
    'host': 'localhost',
    'user': 'your_username',    # Change this
    'password': 'your_password', # Change this
    'database': 'skill_gap_analyzer',
    'charset': 'utf8mb4'
}
```

3. Run the import script:
```bash
python scripts/import_data.py
```

#### Option B: Using SQL Script (If MySQL allows LOAD DATA INFILE)

1. Update the file path in `database/import_actual_data.sql`:
```sql
LOAD DATA INFILE 'D:/ML PROJECT/skill-gap-analyzer/data/raw/skills_database.csv'
```

2. Execute the script:
```bash
mysql -u root -p < database/import_actual_data.sql
```

## Database Schema Overview

### Core Tables

1. **users** - User authentication and profiles
2. **skills** - Master list of skills with categories and demand info
3. **job_professions** - Available job roles and categories
4. **job_skill_requirements** - Mapping between jobs and required skills
5. **resumes** - Uploaded resume files and metadata
6. **resume_skills** - Skills extracted from resumes with confidence scores
7. **skill_analyses** - Complete skill gap analysis results
8. **course_recommendations** - AI-generated course suggestions
9. **skill_trends** - Time series data for skill demand forecasting

### Key Views

- **v_user_analyses** - User analysis summary with job details
- **v_skill_demand_summary** - Skill popularity and demand metrics
- **v_job_skill_matrix** - Complete job-skill requirements matrix
- **v_trending_skills** - Skills with highest growth rates

### Stored Procedures

- **GetUserSkillAnalyses(user_id)** - Get all analyses for a user
- **GetJobRequiredSkills(job_id)** - Get skills required for a job
- **GetSkillTrends(skill_id, months_back)** - Get skill trend data
- **SearchJobs(search_term)** - Search available job professions
- **SearchSkills(search_term)** - Search available skills

## Data Import Results

After running the import script, you should see statistics like:

```
=== IMPORT STATISTICS ===
Skills: 1,247 total, 89 hot technologies, 234 in-demand
Job Professions: 15
Job-Skill Mappings: 1,189 total, 156 critical, 445 important
```

## Sample Queries

### Get all skills for Data Scientist role:
```sql
CALL GetJobRequiredSkills((SELECT id FROM job_professions WHERE name = 'Data Scientist'));
```

### Find trending skills:
```sql
SELECT * FROM v_trending_skills LIMIT 10;
```

### Search for Python-related skills:
```sql
CALL SearchSkills('Python');
```

### Get user dashboard data:
```sql
CALL GetUserDashboardData('user-uuid-here');
```

## Database Connection in Python

Here's how to connect to the database in your Python application:

```python
import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='skill_gap_analyzer',
            user='your_username',
            password='your_password',
            charset='utf8mb4'
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Usage example
connection = get_db_connection()
if connection:
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM skills LIMIT 5")
    results = cursor.fetchall()
    print(results)
    cursor.close()
    connection.close()
```

## Performance Optimization

The database includes several indexes for optimal performance:

- Primary indexes on all ID fields
- Composite indexes for common query patterns
- Text indexes for search functionality
- Foreign key indexes for join operations

## Security Considerations

1. **Password Hashing**: User passwords are hashed using bcrypt
2. **UUID Primary Keys**: Using UUIDs instead of auto-increment integers
3. **Input Validation**: All inputs should be validated before database insertion
4. **Prepared Statements**: Always use parameterized queries to prevent SQL injection

## Backup and Maintenance

### Create Database Backup:
```bash
mysqldump -u root -p skill_gap_analyzer > skill_gap_backup.sql
```

### Restore from Backup:
```bash
mysql -u root -p skill_gap_analyzer < skill_gap_backup.sql
```

### Update Statistics (run periodically):
```sql
ANALYZE TABLE skills, job_professions, job_skill_requirements;
```

## Troubleshooting

### Common Issues:

1. **"Table doesn't exist" error**: Make sure you ran the schema.sql first
2. **Import script fails**: Check file paths and database credentials
3. **Permission denied for LOAD DATA INFILE**: Use the Python import script instead
4. **Character encoding issues**: Ensure your MySQL server uses utf8mb4 charset

### Check Database Status:
```sql
USE skill_gap_analyzer;
SHOW TABLES;
SELECT COUNT(*) FROM skills;
SELECT COUNT(*) FROM job_professions;
```

For additional support, check the main project documentation or create an issue in the project repository.
