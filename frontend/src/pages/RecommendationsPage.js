import React, { useState } from 'react';
import { AcademicCapIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import CourseRecommendations from '../components/recommendations/CourseRecommendations';

const RecommendationsPage = () => {
  const [searchSkills, setSearchSkills] = useState('');
  const [skillList, setSkillList] = useState([]);

  const handleAddSkill = () => {
    if (searchSkills.trim() && !skillList.includes(searchSkills.trim())) {
      setSkillList([...skillList, searchSkills.trim()]);
      setSearchSkills('');
    }
  };

  const handleRemoveSkill = (skillToRemove) => {
    setSkillList(skillList.filter(skill => skill !== skillToRemove));
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleAddSkill();
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Course Recommendations</h1>
        <p className="mt-1 text-gray-600">
          Discover personalized courses to enhance your skills and advance your career
        </p>
      </div>

      {/* Skill Search */}
      <div className="card">
        <div className="card-body">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Find Courses by Skills</h2>
          
          <div className="flex gap-2 mb-4">
            <div className="flex-1 relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Enter a skill (e.g., Python, React, Data Analysis)..."
                value={searchSkills}
                onChange={(e) => setSearchSkills(e.target.value)}
                onKeyPress={handleKeyPress}
                className="input pl-10"
              />
            </div>
            <button
              onClick={handleAddSkill}
              disabled={!searchSkills.trim()}
              className="btn btn-primary px-6"
            >
              Add Skill
            </button>
          </div>

          {skillList.length > 0 && (
            <div>
              <p className="text-sm text-gray-600 mb-2">Skills to find courses for:</p>
              <div className="flex flex-wrap gap-2">
                {skillList.map((skill, index) => (
                  <span
                    key={index}
                    className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-primary-100 text-primary-800"
                  >
                    {skill}
                    <button
                      onClick={() => handleRemoveSkill(skill)}
                      className="ml-2 text-primary-600 hover:text-primary-800"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Course Recommendations */}
      {skillList.length > 0 ? (
        <CourseRecommendations skills={skillList} />
      ) : (
        <div className="text-center py-12">
          <AcademicCapIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            Add skills to get recommendations
          </h3>
          <p className="text-gray-600">
            Enter skills you want to learn or improve to discover relevant courses.
          </p>
        </div>
      )}
    </div>
  );
};

export default RecommendationsPage;
