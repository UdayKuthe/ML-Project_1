import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { 
  CloudArrowUpIcon, 
  DocumentTextIcon,
  XMarkIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { resumeAPI, uploadProgress } from '../../services/api';
import { cn, formatFileSize, isFileTypeAllowed } from '../../utils';
import toast from 'react-hot-toast';

const ALLOWED_FILE_TYPES = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain'
];

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const ResumeUpload = ({ onUploadSuccess, className }) => {
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [selectedFile, setSelectedFile] = useState(null);
  const [error, setError] = useState('');

  const validateFile = (file) => {
    if (!isFileTypeAllowed(file, ALLOWED_FILE_TYPES)) {
      return 'Please upload a PDF, Word document, or text file';
    }
    
    if (file.size > MAX_FILE_SIZE) {
      return `File size must be less than ${formatFileSize(MAX_FILE_SIZE)}`;
    }
    
    return null;
  };

  const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
    setError('');
    
    if (rejectedFiles.length > 0) {
      const rejection = rejectedFiles[0];
      if (rejection.errors.some(e => e.code === 'file-too-large')) {
        setError(`File too large. Maximum size is ${formatFileSize(MAX_FILE_SIZE)}`);
      } else if (rejection.errors.some(e => e.code === 'file-invalid-type')) {
        setError('Invalid file type. Please upload PDF, Word, or text files only.');
      } else {
        setError('File upload failed. Please try again.');
      }
      return;
    }

    if (acceptedFiles.length > 0) {
      const file = acceptedFiles[0];
      const validationError = validateFile(file);
      
      if (validationError) {
        setError(validationError);
        return;
      }

      setSelectedFile(file);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'text/plain': ['.txt']
    },
    maxSize: MAX_FILE_SIZE,
    multiple: false
  });

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    setUploadProgress(0);
    setError('');

    try {
      const response = await resumeAPI.upload(selectedFile, {
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          );
          setUploadProgress(percentCompleted);
        }
      });

      toast.success('Resume uploaded successfully!');
      setSelectedFile(null);
      setUploadProgress(0);
      
      if (onUploadSuccess) {
        onUploadSuccess(response.resume);
      }
    } catch (error) {
      const errorMessage = error.response?.data?.detail || 'Upload failed. Please try again.';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setUploading(false);
    }
  };

  const removeSelectedFile = () => {
    setSelectedFile(null);
    setError('');
    setUploadProgress(0);
  };

  const getFileIcon = (fileType) => {
    if (fileType.includes('pdf')) return '📄';
    if (fileType.includes('word') || fileType.includes('document')) return '📝';
    if (fileType.includes('text')) return '📋';
    return '📄';
  };

  return (
    <div className={cn('w-full', className)}>
      {!selectedFile ? (
        <div
          {...getRootProps()}
          className={cn(
            'dropzone',
            isDragActive && 'active',
            isDragReject && 'rejected',
            error && 'border-error-400'
          )}
        >
          <input {...getInputProps()} />
          <div className="flex flex-col items-center justify-center py-12">
            <CloudArrowUpIcon className="h-12 w-12 text-gray-400 mb-4" />
            {isDragActive ? (
              <p className="text-lg font-medium text-primary-600">
                Drop your resume here...
              </p>
            ) : (
              <>
                <p className="text-lg font-medium text-gray-900 mb-2">
                  Upload your resume
                </p>
                <p className="text-sm text-gray-500 mb-4">
                  Drag and drop your file here, or click to browse
                </p>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                >
                  Choose File
                </button>
              </>
            )}
          </div>
          
          <div className="mt-4 text-xs text-gray-500 text-center">
            <p>Supported formats: PDF, DOC, DOCX, TXT</p>
            <p>Maximum file size: {formatFileSize(MAX_FILE_SIZE)}</p>
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Selected File</h3>
              <button
                onClick={removeSelectedFile}
                className="p-1 text-gray-400 hover:text-gray-600"
                disabled={uploading}
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>

            <div className="flex items-center p-4 bg-gray-50 rounded-lg mb-6">
              <div className="text-2xl mr-3">
                {getFileIcon(selectedFile.type)}
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-900">
                  {selectedFile.name}
                </p>
                <p className="text-xs text-gray-500">
                  {formatFileSize(selectedFile.size)} • {selectedFile.type}
                </p>
              </div>
              {uploading ? (
                <div className="flex items-center">
                  <div className="w-8 h-8 border-2 border-primary-200 border-t-primary-600 rounded-full animate-spin mr-2"></div>
                  <span className="text-sm text-gray-600">{uploadProgress}%</span>
                </div>
              ) : (
                <CheckCircleIcon className="h-5 w-5 text-success-500" />
              )}
            </div>

            {uploading && (
              <div className="mb-6">
                <div className="flex items-center justify-between text-sm text-gray-600 mb-2">
                  <span>Uploading...</span>
                  <span>{uploadProgress}%</span>
                </div>
                <div className="progress-bar h-2">
                  <div 
                    className="progress-fill"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={handleUpload}
                disabled={uploading}
                className={cn(
                  'btn btn-primary flex-1',
                  uploading && 'opacity-50 cursor-not-allowed'
                )}
              >
                {uploading ? 'Uploading...' : 'Upload Resume'}
              </button>
              <button
                onClick={removeSelectedFile}
                disabled={uploading}
                className="btn btn-outline"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 p-4 bg-error-50 border border-error-200 rounded-lg flex items-start">
          <ExclamationTriangleIcon className="h-5 w-5 text-error-500 mt-0.5 mr-3 flex-shrink-0" />
          <div>
            <h4 className="text-sm font-medium text-error-800">Upload Error</h4>
            <p className="text-sm text-error-700">{error}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default ResumeUpload;
