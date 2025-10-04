#!/usr/bin/env python3
"""
Debug specific skill patterns
"""

import re

# Test text containing the skills
sample_text = """
    Skills
    • Programming Languages: Java, C++, C, JavaScript, Dart
    • Tools and Technologies: MERN Stack (MongoDB, Express.js, React.js, Node.js), Flutter, Firebase
    • Databases: MySQL, MongoDB
    • Frontend Development: React.js, HTML, CSS, Tailwind CSS, Bootstrap
    • CS Fundamentals: Data Structures and Algorithms (DSA), problem-solving, DBMS, OOP, CN, OS.
"""

print("Testing specific patterns:")
print("Sample text:", sample_text)
print()

# Test C++ pattern
cpp_patterns = [
    r'\bc\+\+\b',
    r'c\+\+',
    r'\bc\+\+',
    r'c\+\+\b'
]

print("C++ pattern testing:")
for pattern in cpp_patterns:
    matches = re.findall(pattern, sample_text, re.IGNORECASE)
    found = bool(re.search(pattern, sample_text, re.IGNORECASE))
    print(f"  Pattern: {pattern} -> Found: {found}, Matches: {matches}")

print()

# Test Tailwind CSS pattern
tailwind_patterns = [
    r'\btailwind\s+css\b',
    r'\btailwind\s*css\b',
    r'tailwind\s+css',
    r'tailwind css'
]

print("Tailwind CSS pattern testing:")
for pattern in tailwind_patterns:
    matches = re.findall(pattern, sample_text, re.IGNORECASE)
    found = bool(re.search(pattern, sample_text, re.IGNORECASE))
    print(f"  Pattern: {pattern} -> Found: {found}, Matches: {matches}")
