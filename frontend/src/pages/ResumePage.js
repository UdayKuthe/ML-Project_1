import React, { useState } from 'react';
import { PlusIcon, DocumentTextIcon, XMarkIcon } from '@heroicons/react/24/outline';
import ResumeUpload from '../components/resume/ResumeUpload';
import ResumeList from '../components/resume/ResumeList';
import { useQueryClient } from 'react-query';

const ResumePage = () => {
  const [showUpload, setShowUpload] = useState(false);
  const queryClient = useQueryClient();

  const handleUploadSuccess = (resume) => {
    // Refresh the resume list
    queryClient.invalidateQueries('resumes');
    setShowUpload(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Resume Management</h1>
          <p className="mt-1 text-gray-600">
            Upload and manage your resumes for skill analysis
          </p>
        </div>
        <button
          onClick={() => setShowUpload(!showUpload)}
          className="btn btn-primary inline-flex items-center"
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          Upload Resume
        </button>
      </div>

      {/* Upload Section */}
      {showUpload && (
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-gray-900">Upload New Resume</h2>
              <button
                onClick={() => setShowUpload(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>
            <ResumeUpload onUploadSuccess={handleUploadSuccess} />
          </div>
        </div>
      )}

      {/* Resume List */}
      <div className="card">
        <div className="card-body">
          <h2 className="text-lg font-semibold text-gray-900 mb-6">Your Resumes</h2>
          <ResumeList />
        </div>
      </div>
    </div>
  );
};

export default ResumePage;
