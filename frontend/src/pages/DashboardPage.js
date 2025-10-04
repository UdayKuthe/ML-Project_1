import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from 'react-query';
import {
  DocumentTextIcon,
  ChartBarIcon,
  AcademicCapIcon,
  ArrowTrendingUpIcon,
  UserGroupIcon,
  PlusIcon,
  ArrowRightIcon,
} from '@heroicons/react/24/outline';
import { dashboardAPI, resumeAPI, analysisAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { formatDate, cn } from '../utils';

const DashboardPage = () => {
  const { user } = useAuth();

  // Fetch dashboard data
  const { data: stats, isLoading: statsLoading } = useQuery(
    'dashboardStats',
    dashboardAPI.getStats,
    { staleTime: 5 * 60 * 1000 }
  );

  const { data: resumes, isLoading: resumesLoading } = useQuery(
    'userResumes',
    () => resumeAPI.getAll({ limit: 5 }),
    { staleTime: 2 * 60 * 1000 }
  );

  const { data: analyses, isLoading: analysesLoading } = useQuery(
    'recentAnalyses',
    () => analysisAPI.getHistory({ limit: 5 }),
    { staleTime: 2 * 60 * 1000 }
  );

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'text-success-600 bg-success-100';
      case 'processing': return 'text-warning-600 bg-warning-100';
      case 'pending': return 'text-gray-600 bg-gray-100';
      case 'failed': return 'text-error-600 bg-error-100';
      default: return 'text-gray-600 bg-gray-100';
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

  const quickActions = [
    {
      name: 'Upload Resume',
      description: 'Upload a new resume for analysis',
      href: '/resumes',
      icon: DocumentTextIcon,
      color: 'text-primary-600 bg-primary-100',
    },
    {
      name: 'Start Analysis',
      description: 'Analyze skills against job requirements',
      href: '/analysis',
      icon: ChartBarIcon,
      color: 'text-secondary-600 bg-secondary-100',
    },
    {
      name: 'Browse Courses',
      description: 'Explore recommended learning paths',
      href: '/recommendations',
      icon: AcademicCapIcon,
      color: 'text-success-600 bg-success-100',
    },
  ];

  const statCards = [
    {
      name: 'Total Resumes',
      value: stats?.total_resumes || 0,
      icon: DocumentTextIcon,
      color: 'text-primary-600 bg-primary-100',
      description: 'Resumes uploaded',
    },
    {
      name: 'Analyses Completed',
      value: stats?.total_analyses || 0,
      icon: ChartBarIcon,
      color: 'text-secondary-600 bg-secondary-100',
      description: 'Skills analyzed',
    },
    {
      name: 'Average Match',
      value: stats?.average_match_score ? `${Math.round(stats.average_match_score)}%` : '0%',
      icon: ArrowTrendingUpIcon,
      color: 'text-success-600 bg-success-100',
      description: 'Skill compatibility',
    },
    {
      name: 'Courses Found',
      value: stats?.total_recommendations || 0,
      icon: AcademicCapIcon,
      color: 'text-warning-600 bg-warning-100',
      description: 'Learning opportunities',
    },
  ];

  if (statsLoading || resumesLoading || analysesLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner size="large" message="Loading dashboard..." />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Welcome Section */}
      <div className="card">
        <div className="card-body">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Welcome back, {user?.full_name}!
              </h1>
              <p className="mt-1 text-gray-600">
                Track your progress and discover new opportunities to advance your career.
              </p>
            </div>
            <div className="hidden sm:block">
              <Link
                to="/resumes"
                className="btn btn-primary inline-flex items-center"
              >
                <PlusIcon className="w-5 h-5 mr-2" />
                Upload Resume
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat, index) => (
          <div key={index} className="card">
            <div className="card-body">
              <div className="flex items-center">
                <div className={cn('p-3 rounded-lg', stat.color)}>
                  <stat.icon className="h-6 w-6" />
                </div>
                <div className="ml-4">
                  <p className="text-2xl font-semibold text-gray-900">{stat.value}</p>
                  <p className="text-sm text-gray-600">{stat.description}</p>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="card">
        <div className="card-body">
          <h2 className="text-lg font-semibold text-gray-900 mb-6">Quick Actions</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {quickActions.map((action, index) => (
              <Link
                key={index}
                to={action.href}
                className="group p-4 rounded-lg border border-gray-200 hover:border-primary-300 hover:shadow-md transition-all duration-200"
              >
                <div className="flex items-center">
                  <div className={cn('p-2 rounded-lg', action.color)}>
                    <action.icon className="h-5 w-5" />
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-gray-900 group-hover:text-primary-600">
                      {action.name}
                    </p>
                    <p className="text-xs text-gray-500">{action.description}</p>
                  </div>
                  <ArrowRightIcon className="ml-auto h-4 w-4 text-gray-400 group-hover:text-primary-600" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
        {/* Recent Resumes */}
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-gray-900">Recent Resumes</h2>
              <Link
                to="/resumes"
                className="text-sm text-primary-600 hover:text-primary-500 font-medium"
              >
                View all
              </Link>
            </div>
            {resumes?.resumes && resumes.resumes.length > 0 ? (
              <div className="space-y-4">
                {resumes.resumes.slice(0, 5).map((resume) => (
                  <div
                    key={resume.id}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                  >
                    <div className="flex items-center">
                      <DocumentTextIcon className="h-5 w-5 text-gray-400 mr-3" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          {resume.filename}
                        </p>
                        <p className="text-xs text-gray-500">
                          {formatDate(resume.upload_date)}
                        </p>
                      </div>
                    </div>
                    <span
                      className={cn(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                        getStatusColor(resume.status)
                      )}
                    >
                      {getStatusText(resume.status)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900">No resumes yet</h3>
                <p className="mt-1 text-sm text-gray-500">
                  Upload your first resume to get started with analysis.
                </p>
                <div className="mt-6">
                  <Link to="/resumes" className="btn btn-primary btn-sm">
                    Upload Resume
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Recent Analyses */}
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-gray-900">Recent Analyses</h2>
              <Link
                to="/analysis"
                className="text-sm text-primary-600 hover:text-primary-500 font-medium"
              >
                View all
              </Link>
            </div>
            {analyses?.analyses && analyses.analyses.length > 0 ? (
              <div className="space-y-4">
                {analyses.analyses.slice(0, 5).map((analysis) => (
                  <div
                    key={analysis.id}
                    className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                  >
                    <div className="flex items-center">
                      <ChartBarIcon className="h-5 w-5 text-gray-400 mr-3" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          {analysis.job_title || 'Analysis'}
                        </p>
                        <p className="text-xs text-gray-500">
                          {formatDate(analysis.analysis_date)}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-medium text-gray-900">
                        {Math.round(analysis.overall_score || 0)}%
                      </div>
                      <div className="text-xs text-gray-500">match</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <ChartBarIcon className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900">No analyses yet</h3>
                <p className="mt-1 text-sm text-gray-500">
                  Start your first skill gap analysis to see insights here.
                </p>
                <div className="mt-6">
                  <Link to="/analysis" className="btn btn-primary btn-sm">
                    Start Analysis
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Trending Skills */}
      {stats?.trending_skills && stats.trending_skills.length > 0 && (
        <div className="card">
          <div className="card-body">
            <h2 className="text-lg font-semibold text-gray-900 mb-6">Trending Skills</h2>
            <div className="flex flex-wrap gap-2">
              {stats.trending_skills.slice(0, 10).map((skill, index) => (
                <span
                  key={index}
                  className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-primary-100 text-primary-800"
                >
                  <ArrowTrendingUpIcon className="w-3 h-3 mr-1" />
                  {skill}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DashboardPage;
