#!/usr/bin/env python3
"""
Count total number of skills found before the limit
"""

# Import and test with the exact same text as the test
from demo_main import extract_skills_from_text

sample_text = """
    Skills
    • Programming Languages: Java, C++, C, JavaScript, Dart
    • Tools and Technologies: MERN Stack (MongoDB, Express.js, React.js, Node.js), Flutter, Firebase
    • Databases: MySQL, MongoDB
    • Frontend Development: React.js, HTML, CSS, Tailwind CSS, Bootstrap
    • CS Fundamentals: Data Structures and Algorithms (DSA), problem-solving, DBMS, OOP, CN, OS.
"""

# Let's modify the extraction function temporarily to see all skills
import re

# Copy the exact skill patterns from the actual function
skill_patterns = {
    # Programming Languages - exact matches with better patterns
    r'\bjava\b(?!script)': 'Java',  # Java but not JavaScript
    r'c\+\+': 'C++',  # C++ without strict word boundaries
    r'\bc#\b': 'C#',
    r'\b(?<!\w)c(?!\+|#|ss|n|ertif|omputer|loud)\b': 'C',  # C but not C++, C#, CSS, CN, etc.
    r'\bjavascript\b': 'JavaScript',
    r'\bjs\b(?!on)': 'JavaScript',  # js but not json
    r'\btypescript\b': 'TypeScript',
    r'\bpython\b': 'Python',
    r'\bdart\b': 'Dart',
    r'\bphp\b': 'PHP',
    r'\bruby\b': 'Ruby',
    r'\bkotlin\b': 'Kotlin',
    r'\bswift\b': 'Swift',
    r'\bscala\b': 'Scala',
    r'\bgo\b(?!ogle)': 'Go',  # Go but not Google
    r'\br\b(?!eact)': 'R',  # R but not React
    
    # Web Technologies with more precise patterns
    r'\bhtml\b': 'HTML',
    r'\bcss\b(?!\.)': 'CSS',  # CSS but not .css file extension
    r'\breact(?:\.js)?\b': 'React.js',
    r'\bnode(?:\.js)?\b': 'Node.js',
    r'\bexpress(?:\.js)?\b': 'Express.js',
    r'\bangular\b': 'Angular',
    r'\bvue(?:\.js)?\b': 'Vue.js',
    r'\bnext(?:\.js)?\b': 'Next.js',
    r'\bmern\s+stack\b': 'MERN Stack',
    r'\bbootstrap\b': 'Bootstrap',
    r'\btailwind\s+css\b': 'Tailwind CSS',
    r'\bsass\b': 'SASS',
    r'\bscss\b': 'SCSS',
    
    # Databases
    r'\bmysql\b': 'MySQL',
    r'\bmongodb\b': 'MongoDB',
    r'\bmongo\b(?!db)': 'MongoDB',
    r'\bpostgresql\b': 'PostgreSQL',
    r'\bpostgres\b': 'PostgreSQL',
    r'\bredis\b': 'Redis',
    r'\bsqlite\b': 'SQLite',
    r'\boracle\b': 'Oracle',
    r'\bsql\s*server\b': 'SQL Server',
    
    # Mobile & Frameworks
    r'\bflutter\b': 'Flutter',
    r'\bfirebase\b': 'Firebase',
    r'\bandroid\b': 'Android',
    r'\bios\b': 'iOS',
    r'\breact\s*native\b': 'React Native',
    r'\bdjango\b': 'Django',
    r'\bflask\b': 'Flask',
    r'\bfastapi\b': 'FastAPI',
    r'\bspring\b': 'Spring',
    r'\blaravel\b': 'Laravel',
    
    # Concepts and Skills
    r'\boop\b': 'OOP',
    r'\bobject\s*oriented\b': 'OOP',
    r'\bdata\s*structures\b': 'Data Structures',
    r'\balgorithms\b': 'Algorithms',
    r'\bdsa\b': 'Data Structures and Algorithms',
    r'\bdbms\b': 'DBMS',
    r'\bdatabase\s*design\b': 'Database Design',
    r'\bproblem\s*solving\b': 'Problem Solving',
}

text_lower = sample_text.lower()
found_skills = set()

# Find all skills without limit
for pattern, skill_name in skill_patterns.items():
    if re.search(pattern, text_lower, re.IGNORECASE):
        found_skills.add(skill_name)

# Convert to list and sort
all_skills = sorted(list(found_skills))

print(f"Total skills found: {len(all_skills)}")
print("All skills found (alphabetically):")
for i, skill in enumerate(all_skills, 1):
    print(f"{i:2d}. {skill}")

print(f"\nFirst 20 skills (what gets returned):")
for i, skill in enumerate(all_skills[:20], 1):
    print(f"{i:2d}. {skill}")

print(f"\nSkills after position 20 (what gets cut off):")
for i, skill in enumerate(all_skills[20:], 21):
    print(f"{i:2d}. {skill}")

# Check position of React.js and Tailwind CSS
try:
    react_pos = all_skills.index('React.js') + 1
    print(f"\nReact.js is at position: {react_pos}")
except ValueError:
    print("\nReact.js not found in skills!")

try:
    tailwind_pos = all_skills.index('Tailwind CSS') + 1
    print(f"Tailwind CSS is at position: {tailwind_pos}")
except ValueError:
    print("Tailwind CSS not found in skills!")
