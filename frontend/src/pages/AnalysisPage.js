import React from 'react';
import SkillGapAnalysis from '../components/analysis/SkillGapAnalysis';

const AnalysisPage = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Skill Gap Analysis</h1>
        <p className="mt-1 text-gray-600">
          Analyze your skills against job requirements and identify areas for improvement
        </p>
      </div>
      
      <SkillGapAnalysis />
    </div>
  );
};

export default AnalysisPage;
