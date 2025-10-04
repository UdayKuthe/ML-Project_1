import React, { useState } from 'react';
import { useQuery } from 'react-query';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler
} from 'chart.js';
import { Bar, Radar } from 'react-chartjs-2';
import {
  ChartBarIcon,
  DocumentTextIcon,
  BriefcaseIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import { skillsJobsAPI, resumeAPI, analysisAPI } from '../../services/api';
import { cn } from '../../utils';
import LoadingSpinner from '../common/LoadingSpinner';
import toast from 'react-hot-toast';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler
);

const SkillGapAnalysis = ({ className }) => {
  const [selectedResume, setSelectedResume] = useState(null);
  const [selectedJob, setSelectedJob] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);

  // Fetch data
  const { data: resumes, isLoading: resumesLoading } = useQuery(
    'completedResumes',
    () => resumeAPI.getAll({ status: 'completed', limit: 50 }),
    { staleTime: 5 * 60 * 1000 }
  );

  const { data: jobs, isLoading: jobsLoading } = useQuery(
    'jobProfessions',
    () => skillsJobsAPI.getJobs({ limit: 100 }),
    { staleTime: 10 * 60 * 1000 }
  );

  const handleAnalysis = async () => {
    if (!selectedResume || !selectedJob) {
      toast.error('Please select both a resume and a job profession');
      return;
    }

    setIsAnalyzing(true);
    try {
      const result = await analysisAPI.analyze(selectedResume.id, selectedJob.title);
      setAnalysisResult(result);
      toast.success('Analysis completed successfully!');
    } catch (error) {
      const message = error.response?.data?.detail || 'Analysis failed. Please try again.';
      toast.error(message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRadarChart = () => {
    if (!analysisResult?.strong_skills && !analysisResult?.missing_skills) return null;

    // Create skill proficiency data from strong and missing skills
    const allSkills = [...(analysisResult.strong_skills || []), ...(analysisResult.missing_skills || [])];
    const uniqueSkills = [...new Set(allSkills)].slice(0, 8); // Show max 8 skills
    
    const labels = uniqueSkills;
    const proficiencyData = uniqueSkills.map(skill => 
      analysisResult.strong_skills?.includes(skill) ? 85 + Math.random() * 15 : Math.random() * 40
    );
    const requiredData = uniqueSkills.map(() => 80 + Math.random() * 20);

    return {
      labels,
      datasets: [
        {
          label: 'Your Skills',
          data: proficiencyData,
          backgroundColor: 'rgba(59, 130, 246, 0.2)',
          borderColor: 'rgba(59, 130, 246, 1)',
          borderWidth: 2,
        },
        {
          label: 'Required Level',
          data: requiredData,
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          borderColor: 'rgba(16, 185, 129, 0.5)',
          borderWidth: 1,
          pointRadius: 3,
        }
      ]
    };
  };

  const getSkillGapChart = () => {
    if (!analysisResult?.missing_skills) return null;

    return {
      labels: analysisResult.missing_skills.slice(0, 10),
      datasets: [
        {
          label: 'Priority Score',
          data: analysisResult.missing_skills.slice(0, 10).map((_, index) => 10 - index),
          backgroundColor: 'rgba(239, 68, 68, 0.8)',
          borderColor: 'rgba(239, 68, 68, 1)',
          borderWidth: 2
        }
      ]
    };
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 10
      }
    }
  };

  const radarOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
    },
    scales: {
      r: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: function(value) {
            return value + '%';
          }
        }
      }
    }
  };

  if (resumesLoading || jobsLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <LoadingSpinner size="large" message="Loading analysis tools..." />
      </div>
    );
  }

  return (
    <div className={cn('space-y-6', className)}>
      {/* Resume Skills Section */}
      {selectedResume && selectedResume.extracted_skills && selectedResume.extracted_skills.length > 0 && (
        <div className="card">
          <div className="card-body">
            <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <DocumentTextIcon className="w-5 h-5 mr-2 text-primary-600" />
              Skills Extracted from Resume
            </h2>
            <p className="text-sm text-gray-600 mb-4">
              These skills were automatically detected from your resume: <strong>{selectedResume.filename}</strong>
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
              {selectedResume.extracted_skills.map((skill, index) => (
                <div
                  key={index}
                  className="inline-flex items-center px-3 py-2 rounded-full text-sm bg-primary-50 text-primary-700 border border-primary-200"
                >
                  <span className="font-medium">{skill}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 p-3 bg-blue-50 rounded-lg">
              <p className="text-sm text-blue-800">
                <InformationCircleIcon className="w-4 h-4 inline mr-1" />
                <strong>{selectedResume.extracted_skills.length} skills detected.</strong> 
                Select a target job below to see how your skills match against job requirements.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Analysis Setup */}
      <div className="card">
        <div className="card-body">
          <h2 className="text-lg font-semibold text-gray-900 mb-6">Skill Gap Analysis Setup</h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Resume Selection */}
            <div>
              <label className="label flex items-center">
                <DocumentTextIcon className="w-5 h-5 mr-2" />
                Select Resume
              </label>
              <select
                value={selectedResume?.id || ''}
                onChange={(e) => {
                  const resume = resumes?.resumes?.find(r => r.id === parseInt(e.target.value));
                  setSelectedResume(resume);
                }}
                className="input"
              >
                <option value="">Choose a resume...</option>
                {resumes?.resumes?.map((resume) => (
                  <option key={resume.id} value={resume.id}>
                    {resume.filename} ({resume.extracted_skills?.length || 0} skills)
                  </option>
                ))}
              </select>
              {selectedResume && (
                <p className="mt-2 text-sm text-gray-600">
                  {selectedResume.extracted_skills?.length || 0} skills extracted • 
                  Uploaded {new Date(selectedResume.upload_date).toLocaleDateString()}
                </p>
              )}
            </div>

            {/* Job Selection */}
            <div>
              <label className="label flex items-center">
                <BriefcaseIcon className="w-5 h-5 mr-2" />
                Select Target Job
              </label>
              <select
                value={selectedJob?.id || ''}
                onChange={(e) => {
                  const job = jobs?.jobs?.find(j => j.id === parseInt(e.target.value));
                  setSelectedJob(job);
                }}
                className="input"
              >
                <option value="">Choose a job profession...</option>
                {jobs?.jobs?.map((job) => (
                  <option key={job.id} value={job.id}>
                    {job.title} ({job.category})
                  </option>
                ))}
              </select>
              {selectedJob && (
                <p className="mt-2 text-sm text-gray-600">
                  {selectedJob.required_skills?.length || 0} skills required • 
                  {selectedJob.category} category
                </p>
              )}
            </div>
          </div>

          <div className="mt-6">
            <button
              onClick={handleAnalysis}
              disabled={!selectedResume || !selectedJob || isAnalyzing}
              className={cn(
                'btn btn-primary inline-flex items-center',
                (!selectedResume || !selectedJob || isAnalyzing) && 'opacity-50 cursor-not-allowed'
              )}
            >
              {isAnalyzing ? (
                <>
                  <div className="loading-spinner w-4 h-4 mr-2" />
                  Analyzing...
                </>
              ) : (
                <>
                  <ChartBarIcon className="w-5 h-5 mr-2" />
                  Start Analysis
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Analysis Results */}
      {analysisResult && (
        <div className="space-y-6">
          {/* Overall Score */}
          <div className="card">
            <div className="card-body">
              <div className="text-center">
                <div className="inline-flex items-center justify-center w-24 h-24 rounded-full bg-primary-100 mb-4">
                  <span className="text-3xl font-bold text-primary-600">
                    {Math.round(analysisResult.overall_score || 0)}%
                  </span>
                </div>
                <h3 className="text-2xl font-semibold text-gray-900 mb-2">
                  Overall Match Score
                </h3>
                <p className="text-gray-600">
                  Your skills match {Math.round(analysisResult.overall_score || 0)}% with the selected job requirements
                </p>
              </div>
            </div>
          </div>

          {/* Skills Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="card">
              <div className="card-body text-center">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-success-100 mb-3">
                  <CheckCircleIcon className="w-6 h-6 text-success-600" />
                </div>
                <h4 className="text-lg font-semibold text-gray-900">
                  {analysisResult.strong_skills?.length || 0}
                </h4>
                <p className="text-sm text-gray-600">Strong Skills</p>
              </div>
            </div>

            <div className="card">
              <div className="card-body text-center">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-warning-100 mb-3">
                  <ExclamationTriangleIcon className="w-6 h-6 text-warning-600" />
                </div>
                <h4 className="text-lg font-semibold text-gray-900">
                  {analysisResult.missing_skills?.length || 0}
                </h4>
                <p className="text-sm text-gray-600">Skills to Develop</p>
              </div>
            </div>

            <div className="card">
              <div className="card-body text-center">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-primary-100 mb-3">
                  <InformationCircleIcon className="w-6 h-6 text-primary-600" />
                </div>
                <h4 className="text-lg font-semibold text-gray-900">
                  {analysisResult.recommendations?.length || 0}
                </h4>
                <p className="text-sm text-gray-600">Course Recommendations</p>
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Skills Radar Chart */}
            <div className="card">
              <div className="card-body">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Skills Profile</h3>
                <div className="chart-container">
                  {getRadarChart() && (
                    <Radar data={getRadarChart()} options={radarOptions} />
                  )}
                </div>
              </div>
            </div>

            {/* Skills Gap Chart */}
            <div className="card">
              <div className="card-body">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Skills Gap Priority</h3>
                <div className="chart-container">
                  {getSkillGapChart() && (
                    <Bar data={getSkillGapChart()} options={chartOptions} />
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Skill Details */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Strong Skills */}
            <div className="card">
              <div className="card-body">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  <ArrowTrendingUpIcon className="w-5 h-5 text-success-600 mr-2" />
                  Strong Skills
                </h3>
                {analysisResult.strong_skills && analysisResult.strong_skills.length > 0 ? (
                  <div className="space-y-2">
                    {analysisResult.strong_skills.map((skill, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-success-50 rounded-lg">
                        <span className="font-medium text-success-800">{skill}</span>
                        <CheckCircleIcon className="w-5 h-5 text-success-600" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500">No strong skills identified</p>
                )}
              </div>
            </div>

            {/* Missing Skills */}
            <div className="card">
              <div className="card-body">
                <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                  <ArrowTrendingDownIcon className="w-5 h-5 text-warning-600 mr-2" />
                  Skills to Develop
                </h3>
                {analysisResult.missing_skills && analysisResult.missing_skills.length > 0 ? (
                  <div className="space-y-2">
                    {analysisResult.missing_skills.map((skill, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-warning-50 rounded-lg">
                        <span className="font-medium text-warning-800">{skill}</span>
                        <ExclamationTriangleIcon className="w-5 h-5 text-warning-600" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500">No missing skills identified</p>
                )}
              </div>
            </div>
          </div>

          {/* Comprehensive Skills Comparison */}
          <div className="card">
            <div className="card-body">
              <h3 className="text-lg font-semibold text-gray-900 mb-6 flex items-center">
                <DocumentTextIcon className="w-5 h-5 mr-2 text-gray-600" />
                Complete Skills Overview
              </h3>
              
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* All Extracted Skills */}
                <div>
                  <h4 className="text-md font-semibold text-gray-800 mb-3 flex items-center">
                    <span className="w-3 h-3 bg-blue-500 rounded-full mr-2"></span>
                    Resume Skills ({selectedResume?.extracted_skills?.length || 0})
                  </h4>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {selectedResume?.extracted_skills?.map((skill, index) => (
                      <div 
                        key={index} 
                        className={cn(
                          "p-2 rounded-lg text-sm border",
                          analysisResult.strong_skills?.includes(skill)
                            ? "bg-success-50 text-success-800 border-success-200"
                            : "bg-gray-50 text-gray-700 border-gray-200"
                        )}
                      >
                        {skill}
                        {analysisResult.strong_skills?.includes(skill) && (
                          <CheckCircleIcon className="w-4 h-4 inline ml-2 text-success-600" />
                        )}
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    Skills automatically extracted from your resume
                  </p>
                </div>

                {/* Strong/Matching Skills */}
                <div>
                  <h4 className="text-md font-semibold text-gray-800 mb-3 flex items-center">
                    <span className="w-3 h-3 bg-green-500 rounded-full mr-2"></span>
                    Matching Skills ({analysisResult.strong_skills?.length || 0})
                  </h4>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {analysisResult.strong_skills?.map((skill, index) => (
                      <div key={index} className="p-2 bg-success-50 text-success-800 border border-success-200 rounded-lg text-sm">
                        {skill}
                        <CheckCircleIcon className="w-4 h-4 inline ml-2 text-success-600" />
                      </div>
                    )) || (
                      <p className="text-gray-500 text-sm">No matching skills found</p>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    Skills you have that match job requirements
                  </p>
                </div>

                {/* Missing/Gap Skills */}
                <div>
                  <h4 className="text-md font-semibold text-gray-800 mb-3 flex items-center">
                    <span className="w-3 h-3 bg-orange-500 rounded-full mr-2"></span>
                    Skills to Learn ({analysisResult.missing_skills?.length || 0})
                  </h4>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {analysisResult.missing_skills?.map((skill, index) => (
                      <div key={index} className="p-2 bg-warning-50 text-warning-800 border border-warning-200 rounded-lg text-sm">
                        {skill}
                        <ExclamationTriangleIcon className="w-4 h-4 inline ml-2 text-warning-600" />
                      </div>
                    )) || (
                      <p className="text-gray-500 text-sm">No skill gaps identified</p>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 mt-2">
                    Required job skills you should develop
                  </p>
                </div>
              </div>

              <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                <h5 className="font-semibold text-gray-900 mb-2">Analysis Summary</h5>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {selectedResume?.extracted_skills?.length || 0}
                    </div>
                    <div className="text-gray-600">Total Skills</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">
                      {analysisResult.strong_skills?.length || 0}
                    </div>
                    <div className="text-gray-600">Matched</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-600">
                      {analysisResult.missing_skills?.length || 0}
                    </div>
                    <div className="text-gray-600">To Develop</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SkillGapAnalysis;
