#!/usr/bin/env python3
"""
Debug React.js and Tailwind CSS extraction
"""

import re

# Sample text from test
sample_text = """
    Skills
    • Programming Languages: Java, C++, C, JavaScript, Dart
    • Tools and Technologies: MERN Stack (MongoDB, Express.js, React.js, Node.js), Flutter, Firebase
    • Databases: MySQL, MongoDB
    • Frontend Development: React.js, HTML, CSS, Tailwind CSS, Bootstrap
    • CS Fundamentals: Data Structures and Algorithms (DSA), problem-solving, DBMS, OOP, CN, OS.
"""

# Convert to lowercase like the test does
text_lower = sample_text.lower()
print("Lowercase text:", text_lower)
print()

# Test specific patterns
patterns = {
    'React.js': r'\breact(?:\.js)?\b',
    'Tailwind CSS': r'\btailwind\s+css\b'
}

print("Testing patterns on lowercase text:")
for skill_name, pattern in patterns.items():
    matches = re.findall(pattern, text_lower, re.IGNORECASE)
    found = bool(re.search(pattern, text_lower, re.IGNORECASE))
    print(f"{skill_name}: Pattern '{pattern}' -> Found: {found}, Matches: {matches}")

print()

# Also test what the extract_skills_from_text function returns
from demo_main import extract_skills_from_text

extracted = extract_skills_from_text(text_lower)
print("Extracted skills from function:", extracted)
print()

# Check if React.js and Tailwind CSS are in the extracted list
react_in_list = any("react" in skill.lower() for skill in extracted)
tailwind_in_list = any("tailwind" in skill.lower() for skill in extracted)

print(f"React-related skills in extracted list: {react_in_list}")
print(f"Tailwind-related skills in extracted list: {tailwind_in_list}")
