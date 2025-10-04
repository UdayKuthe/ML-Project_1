#!/usr/bin/env python3
"""
Debug step-by-step skill extraction process
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

# Define the exact patterns from the extraction function (subset for testing)
skill_patterns = {
    r'\breact(?:\.js)?\b': 'React.js',
    r'\btailwind\s+css\b': 'Tailwind CSS',
    r'\bhtml\b': 'HTML',
    r'\bcss\b(?!\.)': 'CSS',
    r'\bbootstrap\b': 'Bootstrap',
    r'\bjava\b(?!script)': 'Java',
    r'c\+\+': 'C++',
    r'\bjavascript\b': 'JavaScript'
}

print("Testing specific patterns step by step:")
print("Text:", text_lower)
print()

found_skills = set()

# Test each pattern individually
for pattern, skill_name in skill_patterns.items():
    match = re.search(pattern, text_lower, re.IGNORECASE)
    if match:
        found_skills.add(skill_name)
        print(f"✅ Pattern '{pattern}' -> Matched: '{match.group()}' -> Skill: '{skill_name}'")
    else:
        print(f"❌ Pattern '{pattern}' -> No match -> Skill: '{skill_name}'")

print()
print("Found skills set:", found_skills)
print("Found skills list (sorted):", sorted(list(found_skills)))

print()
print("Testing with the actual extraction function:")
from demo_main import extract_skills_from_text
actual_result = extract_skills_from_text(text_lower)
print("Actual function result:", actual_result)

# Check if our expected skills are in the result
print()
print("Checking for specific skills:")
react_in_result = 'React.js' in actual_result
tailwind_in_result = 'Tailwind CSS' in actual_result
print(f"React.js in result: {react_in_result}")
print(f"Tailwind CSS in result: {tailwind_in_result}")
