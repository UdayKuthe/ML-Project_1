#!/usr/bin/env python3
"""
Test script for skill extraction functionality
"""

# Import the skill extraction function
from demo_main import extract_skills_from_text

def test_skill_extraction():
    # Sample resume text based on the image you showed
    sample_resume_text = """
    Skills
    • Programming Languages: Java, C++, C, JavaScript, Dart
    • Tools and Technologies: MERN Stack (MongoDB, Express.js, React.js, Node.js), Flutter, Firebase
    • Databases: MySQL, MongoDB
    • Frontend Development: React.js, HTML, CSS, Tailwind CSS, Bootstrap
    • CS Fundamentals: Data Structures and Algorithms (DSA), problem-solving, DBMS, OOP, CN, OS.
    """
    
    print("Testing skill extraction...")
    print("Sample text:")
    print(sample_resume_text)
    print("\n" + "="*50)
    
    # Extract skills
    extracted_skills = extract_skills_from_text(sample_resume_text.lower())
    
    print(f"Extracted skills ({len(extracted_skills)}):")
    for i, skill in enumerate(extracted_skills, 1):
        print(f"{i}. {skill}")
    
    print("\n" + "="*50)
    print("Expected skills from resume:")
    expected = [
        "Java", "C++", "C", "JavaScript", "Dart",
        "MongoDB", "Express.js", "React.js", "Node.js", "Flutter", "Firebase",
        "MySQL", "MongoDB", "React.js", "HTML", "CSS", "Tailwind CSS", "Bootstrap",
        "Data Structures", "Algorithms", "DBMS", "OOP"
    ]
    
    for skill in expected:
        print(f"- {skill}")
    
    print("\n" + "="*50)
    print("Match analysis:")
    matched = 0
    for exp_skill in expected:
        found = False
        matched_with = None
        
        # First try exact match (case insensitive)
        for ext_skill in extracted_skills:
            if exp_skill.lower() == ext_skill.lower():
                found = True
                matched_with = ext_skill
                break
        
        # If no exact match, try fuzzy matching for common variations
        if not found:
            for ext_skill in extracted_skills:
                exp_lower = exp_skill.lower()
                ext_lower = ext_skill.lower()
                
                # Handle common variations
                if (exp_lower == "react.js" and ext_lower == "react") or \
                   (exp_lower == "react" and ext_lower == "react.js") or \
                   (exp_lower == "node.js" and ext_lower == "node") or \
                   (exp_lower == "node" and ext_lower == "node.js") or \
                   (exp_lower == "express.js" and ext_lower == "express") or \
                   (exp_lower == "express" and ext_lower == "express.js") or \
                   (exp_lower == "data structures and algorithms" and ext_lower == "dsa") or \
                   (exp_lower == "dsa" and ext_lower == "data structures and algorithms"):
                    found = True
                    matched_with = ext_skill
                    break
        
        if found:
            print(f"✅ {exp_skill} -> {matched_with}")
            matched += 1
        else:
            print(f"❌ {exp_skill} -> Not found")
    
    print(f"\nMatch rate: {matched}/{len(expected)} ({matched/len(expected)*100:.1f}%)")

if __name__ == "__main__":
    test_skill_extraction()
