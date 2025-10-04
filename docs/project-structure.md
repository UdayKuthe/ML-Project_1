# Skill Gap Analyzer - Project Structure & Workflow

## 1. Project Directory Structure

```mermaid
graph TB
    A[skill-gap-analyzer/] --> B[backend/]
    A --> C[frontend/]
    A --> D[data/]
    A --> E[docs/]
    A --> F[database/]
    
    B --> B1[main.py]
    B --> B2[run.py]
    B --> B3[config.py]
    B --> B4[requirements.txt]
    B --> B5[routers/]
    B --> B6[services/]
    B --> B7[utils/]
    B --> B8[models/]
    B --> B9[tests/]
    
    B5 --> B5a[auth.py]
    B5 --> B5b[resumes.py]
    B5 --> B5c[skills_jobs.py]
    B5 --> B5d[analysis.py]
    
    B6 --> B6a[skill_extractor.py]
    B6 --> B6b[nlp_trainer.py]
    B6 --> B6c[skill_gap_engine.py]
    B6 --> B6d[course_recommender.py]
    
    B7 --> B7a[database.py]
    B7 --> B7b[auth_utils.py]
    B7 --> B7c[file_processor.py]
    
    B8 --> B8a[schemas.py]
    
    C --> C1[src/]
    C --> C2[public/]
    C --> C3[package.json]
    C --> C4[tailwind.config.js]
    
    C1 --> C1a[components/]
    C1 --> C1b[pages/]
    C1 --> C1c[services/]
    C1 --> C1d[utils/]
    C1 --> C1e[App.js]
    C1 --> C1f[index.js]
    
    C1a --> C1a1[auth/]
    C1a --> C1a2[common/]
    C1a --> C1a3[resume/]
    C1a --> C1a4[analysis/]
    C1a --> C1a5[recommendations/]
    
    D --> D1[raw/]
    D --> D2[processed/]
    D --> D3[models/]
    
    D1 --> D1a[resume_dataset.csv]
    D1 --> D1b[skill_ontology.csv]
    D1 --> D1c[job_postings.csv]
    
    F --> F1[schema.sql]
    F --> F2[seed_data.sql]
    F --> F3[stored_procedures.sql]
    F --> F4[README.md]
```

## 2. System Architecture & Data Flow

```mermaid
graph LR
    A[User Interface<br/>React + Tailwind] --> B[FastAPI Backend<br/>Python]
    B --> C[MySQL Database]
    B --> D[ML/NLP Services<br/>spaCy, SBERT, scikit-learn]
    B --> E[File Processing<br/>PDF, DOCX, TXT]
    B --> F[External APIs<br/>Course Platforms]
    
    D --> D1[Skill Extraction]
    D --> D2[Semantic Matching]
    D --> D3[Gap Analysis]
    
    C --> C1[Users & Auth]
    C --> C2[Resumes & Skills]
    C --> C3[Jobs & Requirements]
    C --> C4[Analysis Results]
    
    F --> F1[Coursera API]
    F --> F2[Udemy API]
    F --> F3[edX API]
```

## 3. Complete Application Workflow

```mermaid
flowchart TD
    Start([User Starts Application]) --> Login{User Authenticated?}
    
    Login -->|No| Auth[Authentication Page]
    Auth --> Register[Register/Login]
    Register --> Dashboard
    
    Login -->|Yes| Dashboard[Dashboard]
    
    Dashboard --> Upload{Upload Resume?}
    Dashboard --> Browse{Browse Skills/Jobs?}
    Dashboard --> Analyze{Perform Analysis?}
    Dashboard --> Recommend{Get Recommendations?}
    
    %% Resume Upload Flow
    Upload -->|Yes| FileUpload[File Upload Component]
    FileUpload --> FileValidation{Valid File?}
    FileValidation -->|No| UploadError[Show Error Message]
    UploadError --> FileUpload
    
    FileValidation -->|Yes| TextExtraction[Extract Text from File]
    TextExtraction --> SkillExtraction[NLP Skill Extraction<br/>spaCy + Regex]
    SkillExtraction --> SaveResume[Save to Database]
    SaveResume --> ResumeList[Display Resume List]
    ResumeList --> Dashboard
    
    %% Browse Flow
    Browse -->|Yes| BrowsePage[Skills & Jobs Browser]
    BrowsePage --> SearchFilter[Search & Filter Options]
    SearchFilter --> DisplayResults[Display Paginated Results]
    DisplayResults --> Dashboard
    
    %% Analysis Flow
    Analyze -->|Yes| SelectResume[Select Resume]
    SelectResume --> SelectJob[Select Target Job]
    SelectJob --> RunAnalysis[Skill Gap Analysis Engine]
    
    RunAnalysis --> SemanticMatch[SBERT Semantic Matching]
    SemanticMatch --> FuzzyMatch[Fuzzy String Matching]
    FuzzyMatch --> GapCalculation[Calculate Skill Gaps]
    GapCalculation --> ScoreGeneration[Generate Overall Score]
    ScoreGeneration --> Visualization[Create Charts<br/>Chart.js - Radar & Bar]
    Visualization --> AnalysisResults[Display Analysis Results]
    AnalysisResults --> Dashboard
    
    %% Recommendation Flow
    Recommend -->|Yes| GetRecommendations[Course Recommendation Engine]
    GetRecommendations --> IdentifyGaps[Identify Missing Skills]
    IdentifyGaps --> SearchCourses[Search External APIs]
    
    SearchCourses --> CourseraAPI[Coursera API]
    SearchCourses --> UdemyAPI[Udemy API]
    SearchCourses --> EdxAPI[edX API]
    
    CourseraAPI --> AggregateCourses[Aggregate & Rank Courses]
    UdemyAPI --> AggregateCourses
    EdxAPI --> AggregateCourses
    
    AggregateCourses --> FilterSort[Filter & Sort Options]
    FilterSort --> DisplayCourses[Display Course Grid/List]
    DisplayCourses --> BookmarkCourse{Bookmark Course?}
    
    BookmarkCourse -->|Yes| SaveBookmark[Save to Database]
    SaveBookmark --> DisplayCourses
    BookmarkCourse -->|No| Dashboard
    DisplayCourses --> Dashboard
    
    Dashboard --> Logout{Logout?}
    Logout -->|Yes| End([End Session])
    Logout -->|No| Dashboard
```

## 4. Database Schema Relationships

```mermaid
erDiagram
    USERS {
        int id PK
        varchar email UK
        varchar password_hash
        varchar full_name
        datetime created_at
        datetime updated_at
        boolean is_active
    }
    
    RESUMES {
        int id PK
        int user_id FK
        varchar filename
        text original_text
        json extracted_skills
        varchar file_path
        datetime uploaded_at
        datetime processed_at
        enum status
    }
    
    SKILLS {
        int id PK
        varchar name UK
        varchar category
        text description
        varchar aliases
        float importance_weight
        boolean is_active
        datetime created_at
        datetime updated_at
    }
    
    JOBS {
        int id PK
        varchar title
        varchar company
        text description
        json required_skills
        json preferred_skills
        varchar location
        varchar experience_level
        float salary_range_min
        float salary_range_max
        datetime posted_at
        boolean is_active
    }
    
    SKILL_GAP_ANALYSES {
        int id PK
        int user_id FK
        int resume_id FK
        int job_id FK
        json analysis_results
        float overall_match_score
        json skill_gaps
        json recommendations
        datetime created_at
    }
    
    COURSE_BOOKMARKS {
        int id PK
        int user_id FK
        varchar course_id
        varchar course_title
        varchar provider
        varchar course_url
        datetime bookmarked_at
    }
    
    USERS ||--o{ RESUMES : "has"
    USERS ||--o{ SKILL_GAP_ANALYSES : "performs"
    USERS ||--o{ COURSE_BOOKMARKS : "bookmarks"
    RESUMES ||--o{ SKILL_GAP_ANALYSES : "analyzed_in"
    JOBS ||--o{ SKILL_GAP_ANALYSES : "compared_with"
```

## 5. ML/NLP Pipeline Workflow

```mermaid
flowchart LR
    A[Raw Resume Text] --> B[Text Preprocessing]
    B --> C[Skill Extraction Pipeline]
    
    C --> C1[Regex Pattern Matching]
    C --> C2[spaCy NER]
    C --> C3[Fuzzy Matching]
    
    C1 --> D[Skill Normalization]
    C2 --> D
    C3 --> D
    
    D --> E[SBERT Embeddings]
    E --> F[Semantic Similarity]
    F --> G[Job Matching Algorithm]
    
    G --> H[Gap Analysis Engine]
    H --> I[Skill Classification]
    I --> I1[Strong Skills]
    I --> I2[Moderate Skills]
    I --> I3[Missing Skills]
    
    I1 --> J[Visualization Generation]
    I2 --> J
    I3 --> J
    
    J --> K[Analysis Results]
    I3 --> L[Course Recommendation Engine]
    L --> M[External API Integration]
    M --> N[Ranked Course Suggestions]
```

## 6. API Architecture

```mermaid
graph TB
    A[Frontend React App] --> B[FastAPI Main App]
    
    B --> B1[Authentication Router<br/>/api/v1/auth]
    B --> B2[Resume Router<br/>/api/v1/resumes]
    B --> B3[Skills & Jobs Router<br/>/api/v1/skills-jobs]
    B --> B4[Analysis Router<br/>/api/v1/analysis]
    
    B1 --> B1a[POST /register]
    B1 --> B1b[POST /login]
    B1 --> B1c[GET /me]
    B1 --> B1d[POST /logout]
    
    B2 --> B2a[POST /upload]
    B2 --> B2b[GET /]
    B2 --> B2c[GET /{id}]
    B2 --> B2d[DELETE /{id}]
    B2 --> B2e[POST /{id}/reprocess]
    
    B3 --> B3a[GET /skills]
    B3 --> B3b[GET /jobs]
    B3 --> B3c[GET /skills/search]
    B3 --> B3d[GET /jobs/search]
    
    B4 --> B4a[POST /analyze]
    B4 --> B4b[GET /history]
    B4 --> B4c[POST /recommend-courses]
    B4 --> B4d[GET /bookmarks]
    B4 --> B4e[POST /bookmark]
    
    B1a --> C[MySQL Database]
    B1b --> C
    B1c --> C
    B2a --> C
    B2b --> C
    B3a --> C
    B3b --> C
    B4a --> C
    
    B2a --> D[File Processing Service]
    B4a --> E[ML/NLP Services]
    B4c --> F[Course APIs]
```
