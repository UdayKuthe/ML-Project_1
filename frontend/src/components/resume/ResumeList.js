import React, { useState } from 'react';
import { useQuery, useQueryClient } from 'react-query';
import {
  DocumentTextIcon,
  EyeIcon,
  TrashIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ChevronDownIcon
} from '@heroicons/react/24/outline';
import { resumeAPI } from '../../services/api';
import { cn, formatDate, formatFileSize } from '../../utils';
import LoadingSpinner from '../common/LoadingSpinner';
import toast from 'react-hot-toast';

const ResumeList = ({ onResumeSelect, className }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState('upload_date');
  const [sortOrder, setSortOrder] = useState('desc');
  const queryClient = useQueryClient();

  const { data: resumes, isLoading, error, refetch } = useQuery(
    ['resumes', { search: searchTerm, status: statusFilter, sort: sortBy, order: sortOrder }],
    () => resumeAPI.getAll({
      search: searchTerm || undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
      sort_by: sortBy,
      sort_order: sortOrder,
      limit: 50
    }),
    {
      staleTime: 30 * 1000, // 30 seconds
      refetchInterval: 5 * 1000, // Refetch every 5 seconds for processing status updates
    }
  );

  const handleDelete = async (resumeId, filename) => {
    if (!window.confirm(`Are you sure you want to delete "${filename}"?`)) {
      return;
    }

    try {
      await resumeAPI.delete(resumeId);
      toast.success('Resume deleted successfully');
      queryClient.invalidateQueries('resumes');
    } catch (error) {
      const message = error.response?.data?.detail || 'Failed to delete resume';
      toast.error(message);
    }
  };

  const handleReprocess = async (resumeId, filename) => {
    if (!window.confirm(`Reprocess skills extraction for "${filename}"?`)) {
      return;
    }

    try {
      await resumeAPI.reprocess(resumeId);
      toast.success('Resume reprocessing started');
      queryClient.invalidateQueries('resumes');
    } catch (error) {
      const message = error.response?.data?.detail || 'Failed to reprocess resume';
      toast.error(message);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-success-100 text-success-800 border-success-200';
      case 'processing':
        return 'bg-warning-100 text-warning-800 border-warning-200';
      case 'pending':
        return 'bg-gray-100 text-gray-800 border-gray-200';
      case 'failed':
        return 'bg-error-100 text-error-800 border-error-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'completed': return 'Completed';
      case 'processing': return 'Processing';
      case 'pending': return 'Pending';
      case 'failed': return 'Failed';
      default: return 'Unknown';
    }
  };

  const getFileIcon = (fileType) => {
    if (fileType?.includes('pdf')) return '📄';
    if (fileType?.includes('word') || fileType?.includes('document')) return '📝';
    if (fileType?.includes('text')) return '📋';
    return '📄';
  };

  const filteredResumes = resumes?.resumes || [];

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <LoadingSpinner size="large" message="Loading resumes..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <div className="text-error-500 mb-4">
          <DocumentTextIcon className="mx-auto h-12 w-12" />
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load resumes</h3>
        <p className="text-gray-600 mb-6">There was an error loading your resumes.</p>
        <button
          onClick={() => refetch()}
          className="btn btn-primary inline-flex items-center"
        >
          <ArrowPathIcon className="w-4 h-4 mr-2" />
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className={cn('space-y-6', className)}>
      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search resumes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input pl-10"
          />
        </div>
        
        <div className="flex gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input pr-8"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="processing">Processing</option>
            <option value="pending">Pending</option>
            <option value="failed">Failed</option>
          </select>

          <select
            value={`${sortBy}-${sortOrder}`}
            onChange={(e) => {
              const [field, order] = e.target.value.split('-');
              setSortBy(field);
              setSortOrder(order);
            }}
            className="input pr-8"
          >
            <option value="upload_date-desc">Newest First</option>
            <option value="upload_date-asc">Oldest First</option>
            <option value="filename-asc">Name A-Z</option>
            <option value="filename-desc">Name Z-A</option>
            <option value="file_size-desc">Largest First</option>
            <option value="file_size-asc">Smallest First</option>
          </select>
        </div>
      </div>

      {/* Resume List */}
      {filteredResumes.length === 0 ? (
        <div className="text-center py-12">
          <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            {searchTerm || statusFilter !== 'all' ? 'No resumes match your filters' : 'No resumes uploaded yet'}
          </h3>
          <p className="text-gray-600 mb-6">
            {searchTerm || statusFilter !== 'all' 
              ? 'Try adjusting your search terms or filters.'
              : 'Upload your first resume to get started with skill analysis.'
            }
          </p>
          {!searchTerm && statusFilter === 'all' && (
            <button className="btn btn-primary">
              Upload Resume
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredResumes.map((resume) => (
            <div key={resume.id} className="card hover:shadow-md transition-shadow">
              <div className="card-body">
                <div className="flex items-center justify-between">
                  <div className="flex items-center flex-1 min-w-0">
                    <div className="text-2xl mr-4 flex-shrink-0">
                      {getFileIcon(resume.file_type)}
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <h3 className="text-lg font-semibold text-gray-900 truncate">
                        {resume.filename}
                      </h3>
                      <div className="flex flex-wrap items-center gap-4 mt-1 text-sm text-gray-600">
                        <span>
                          {formatFileSize(resume.file_size)}
                        </span>
                        <span>
                          Uploaded {formatDate(resume.upload_date)}
                        </span>
                        {resume.skill_count > 0 && (
                          <span className="inline-flex items-center">
                            <span className="w-2 h-2 bg-primary-500 rounded-full mr-1"></span>
                            {resume.skill_count} skills found
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 ml-4">
                    <span
                      className={cn(
                        'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border',
                        getStatusColor(resume.status)
                      )}
                    >
                      {getStatusText(resume.status)}
                      {resume.processing_status === 'processing' && (
                        <div className="ml-2 w-3 h-3 border border-current border-t-transparent rounded-full animate-spin"></div>
                      )}
                    </span>

                    <div className="flex items-center gap-1">
                      {onResumeSelect && (
                        <button
                          onClick={() => onResumeSelect(resume)}
                          className="p-2 text-gray-400 hover:text-primary-600 hover:bg-primary-50 rounded-lg transition-colors"
                          title="Select resume"
                        >
                          <EyeIcon className="h-5 w-5" />
                        </button>
                      )}

                      {resume.processing_status === 'failed' && (
                        <button
                          onClick={() => handleReprocess(resume.id, resume.filename)}
                          className="p-2 text-gray-400 hover:text-warning-600 hover:bg-warning-50 rounded-lg transition-colors"
                          title="Reprocess resume"
                        >
                          <ArrowPathIcon className="h-5 w-5" />
                        </button>
                      )}

                      <button
                        onClick={() => handleDelete(resume.id, resume.filename)}
                        className="p-2 text-gray-400 hover:text-error-600 hover:bg-error-50 rounded-lg transition-colors"
                        title="Delete resume"
                      >
                        <TrashIcon className="h-5 w-5" />
                      </button>
                    </div>
                  </div>
                </div>

                {resume.extracted_skills && resume.extracted_skills.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-gray-100">
                    <div className="flex flex-wrap gap-2">
                      {resume.extracted_skills.slice(0, 8).map((skill, index) => (
                        <span
                          key={index}
                          className="inline-flex items-center px-2 py-1 rounded-md text-xs bg-primary-100 text-primary-800"
                        >
                          {skill}
                        </span>
                      ))}
                      {resume.extracted_skills.length > 8 && (
                        <span className="inline-flex items-center px-2 py-1 rounded-md text-xs bg-gray-100 text-gray-600">
                          +{resume.extracted_skills.length - 8} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Results Summary */}
      {filteredResumes.length > 0 && (
        <div className="flex justify-between items-center text-sm text-gray-600 pt-4 border-t">
          <span>
            Showing {filteredResumes.length} resume{filteredResumes.length !== 1 ? 's' : ''}
          </span>
          <button
            onClick={() => refetch()}
            className="inline-flex items-center text-primary-600 hover:text-primary-500"
          >
            <ArrowPathIcon className="w-4 h-4 mr-1" />
            Refresh
          </button>
        </div>
      )}
    </div>
  );
};

export default ResumeList;
