import React, { useState, useEffect } from 'react';
import { useQuery } from 'react-query';
import {
  AcademicCapIcon,
  StarIcon,
  ClockIcon,
  CurrencyDollarIcon,
  ArrowTopRightOnSquareIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  BookmarkIcon,
  PlayIcon,
  CheckBadgeIcon
} from '@heroicons/react/24/outline';
import { StarIcon as StarIconSolid } from '@heroicons/react/24/solid';
import { courseAPI, analysisAPI } from '../../services/api';
import { cn, formatDate } from '../../utils';
import LoadingSpinner from '../common/LoadingSpinner';
import toast from 'react-hot-toast';

const CourseRecommendations = ({ analysisId, skills = [], className }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('all');
  const [selectedLevel, setSelectedLevel] = useState('all');
  const [selectedPriceRange, setSelectedPriceRange] = useState('all');
  const [sortBy, setSortBy] = useState('relevance');
  const [viewMode, setViewMode] = useState('grid');
  const [bookmarkedCourses, setBookmarkedCourses] = useState(new Set());

  // Fetch course recommendations
  const { data: recommendations, isLoading, error, refetch } = useQuery(
    ['courseRecommendations', analysisId, skills, searchTerm, selectedProvider, selectedLevel, selectedPriceRange, sortBy],
    async () => {
      if (analysisId) {
        // Get recommendations from analysis
        const analysis = await analysisAPI.getById(analysisId);
        return analysis.recommendations || [];
      } else if (skills.length > 0) {
        // Get recommendations for specific skills
        return await courseAPI.getRecommendations(skills, {
          provider: selectedProvider !== 'all' ? selectedProvider : undefined,
          level: selectedLevel !== 'all' ? selectedLevel : undefined,
          price_range: selectedPriceRange !== 'all' ? selectedPriceRange : undefined,
          search: searchTerm || undefined,
          sort_by: sortBy
        });
      }
      return [];
    },
    {
      enabled: !!(analysisId || skills.length > 0),
      staleTime: 5 * 60 * 1000
    }
  );

  const handleBookmark = (courseId) => {
    setBookmarkedCourses(prev => {
      const newSet = new Set(prev);
      if (newSet.has(courseId)) {
        newSet.delete(courseId);
        toast.success('Course removed from bookmarks');
      } else {
        newSet.add(courseId);
        toast.success('Course bookmarked');
      }
      return newSet;
    });
  };

  const getPriorityColor = (priority) => {
    switch (priority?.toLowerCase()) {
      case 'high':
        return 'bg-error-100 text-error-800 border-error-200';
      case 'medium':
        return 'bg-warning-100 text-warning-800 border-warning-200';
      case 'low':
        return 'bg-primary-100 text-primary-800 border-primary-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getLevelColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'beginner':
        return 'bg-success-100 text-success-800';
      case 'intermediate':
        return 'bg-warning-100 text-warning-800';
      case 'advanced':
        return 'bg-error-100 text-error-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getProviderLogo = (provider) => {
    const logos = {
      'coursera': '🎓',
      'udemy': '📚',
      'edx': '🏛️',
      'linkedin': '💼',
      'pluralsight': '⚡',
      'skillshare': '🎨',
      'udacity': '🚀'
    };
    return logos[provider.toLowerCase()] || '📖';
  };

  const filteredRecommendations = recommendations?.filter(course => {
    const matchesSearch = !searchTerm || 
      course.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      course.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      course.skills_covered?.some(skill => skill.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesProvider = selectedProvider === 'all' || 
      course.provider.toLowerCase() === selectedProvider.toLowerCase();
    
    const matchesLevel = selectedLevel === 'all' || 
      course.level.toLowerCase() === selectedLevel.toLowerCase();
    
    const matchesPrice = selectedPriceRange === 'all' || 
      (selectedPriceRange === 'free' && course.price === 0) ||
      (selectedPriceRange === 'paid' && course.price > 0) ||
      (selectedPriceRange === 'under50' && course.price <= 50) ||
      (selectedPriceRange === 'under100' && course.price <= 100);
    
    return matchesSearch && matchesProvider && matchesLevel && matchesPrice;
  }) || [];

  const sortedRecommendations = filteredRecommendations.sort((a, b) => {
    switch (sortBy) {
      case 'relevance':
        return (b.relevance_score || 0) - (a.relevance_score || 0);
      case 'rating':
        return (b.rating || 0) - (a.rating || 0);
      case 'price_low':
        return (a.price || 0) - (b.price || 0);
      case 'price_high':
        return (b.price || 0) - (a.price || 0);
      case 'duration':
        return (a.duration || '').localeCompare(b.duration || '');
      default:
        return 0;
    }
  });

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <LoadingSpinner size="large" message="Loading course recommendations..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AcademicCapIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Failed to load recommendations</h3>
        <p className="text-gray-600 mb-6">There was an error loading course recommendations.</p>
        <button
          onClick={() => refetch()}
          className="btn btn-primary"
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className={cn('space-y-6', className)}>
      {/* Filters and Search */}
      <div className="card">
        <div className="card-body">
          <div className="flex flex-col lg:flex-row gap-4">
            {/* Search */}
            <div className="flex-1 relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search courses..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input pl-10"
              />
            </div>

            {/* Filters */}
            <div className="flex flex-wrap gap-2">
              <select
                value={selectedProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
                className="input"
              >
                <option value="all">All Providers</option>
                <option value="coursera">Coursera</option>
                <option value="udemy">Udemy</option>
                <option value="edx">edX</option>
                <option value="linkedin">LinkedIn Learning</option>
                <option value="pluralsight">Pluralsight</option>
              </select>

              <select
                value={selectedLevel}
                onChange={(e) => setSelectedLevel(e.target.value)}
                className="input"
              >
                <option value="all">All Levels</option>
                <option value="beginner">Beginner</option>
                <option value="intermediate">Intermediate</option>
                <option value="advanced">Advanced</option>
              </select>

              <select
                value={selectedPriceRange}
                onChange={(e) => setSelectedPriceRange(e.target.value)}
                className="input"
              >
                <option value="all">All Prices</option>
                <option value="free">Free</option>
                <option value="under50">Under $50</option>
                <option value="under100">Under $100</option>
                <option value="paid">Paid</option>
              </select>

              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="input"
              >
                <option value="relevance">Most Relevant</option>
                <option value="rating">Highest Rated</option>
                <option value="price_low">Price: Low to High</option>
                <option value="price_high">Price: High to Low</option>
                <option value="duration">Duration</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Results Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">
            Course Recommendations
          </h2>
          <p className="text-sm text-gray-600">
            {sortedRecommendations.length} course{sortedRecommendations.length !== 1 ? 's' : ''} found
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setViewMode('grid')}
            className={cn(
              'p-2 rounded-lg',
              viewMode === 'grid' ? 'bg-primary-100 text-primary-600' : 'bg-gray-100 text-gray-600'
            )}
          >
            <div className="w-4 h-4 grid grid-cols-2 gap-0.5">
              <div className="bg-current rounded-sm"></div>
              <div className="bg-current rounded-sm"></div>
              <div className="bg-current rounded-sm"></div>
              <div className="bg-current rounded-sm"></div>
            </div>
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={cn(
              'p-2 rounded-lg',
              viewMode === 'list' ? 'bg-primary-100 text-primary-600' : 'bg-gray-100 text-gray-600'
            )}
          >
            <div className="w-4 h-4 flex flex-col gap-0.5">
              <div className="bg-current h-0.5 rounded-full"></div>
              <div className="bg-current h-0.5 rounded-full"></div>
              <div className="bg-current h-0.5 rounded-full"></div>
              <div className="bg-current h-0.5 rounded-full"></div>
            </div>
          </button>
        </div>
      </div>

      {/* Course List */}
      {sortedRecommendations.length === 0 ? (
        <div className="text-center py-12">
          <AcademicCapIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No courses found</h3>
          <p className="text-gray-600">
            Try adjusting your search terms or filters to find relevant courses.
          </p>
        </div>
      ) : (
        <div className={cn(
          viewMode === 'grid' 
            ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'
            : 'space-y-4'
        )}>
          {sortedRecommendations.map((course) => (
            <div key={course.id} className="card hover:shadow-md transition-shadow">
              <div className="card-body">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{getProviderLogo(course.provider)}</span>
                    <span className="text-sm text-gray-600">{course.provider}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {course.priority && (
                      <span className={cn(
                        'px-2 py-1 rounded-full text-xs font-medium border',
                        getPriorityColor(course.priority)
                      )}>
                        {course.priority}
                      </span>
                    )}
                    <button
                      onClick={() => handleBookmark(course.id)}
                      className={cn(
                        'p-1 rounded-full transition-colors',
                        bookmarkedCourses.has(course.id)
                          ? 'text-warning-600 bg-warning-50'
                          : 'text-gray-400 hover:text-gray-600'
                      )}
                    >
                      <BookmarkIcon className="w-5 h-5" />
                    </button>
                  </div>
                </div>

                <h3 className="text-lg font-semibold text-gray-900 mb-2 line-clamp-2">
                  {course.title}
                </h3>

                <p className="text-sm text-gray-600 mb-3 line-clamp-2">
                  {course.description}
                </p>

                <div className="flex items-center gap-4 mb-3 text-sm text-gray-600">
                  <div className="flex items-center gap-1">
                    <StarIcon className="w-4 h-4" />
                    <span>{course.rating || 'N/A'}</span>
                  </div>
                  
                  <div className="flex items-center gap-1">
                    <ClockIcon className="w-4 h-4" />
                    <span>{course.duration || 'N/A'}</span>
                  </div>

                  <div className="flex items-center gap-1">
                    <CurrencyDollarIcon className="w-4 h-4" />
                    <span>
                      {course.price === 0 ? 'Free' : `$${course.price}`}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between mb-4">
                  <span className={cn(
                    'px-2 py-1 rounded-full text-xs font-medium',
                    getLevelColor(course.level)
                  )}>
                    {course.level}
                  </span>
                  
                  {course.relevance_score && (
                    <span className="text-xs text-gray-500">
                      {Math.round(course.relevance_score * 100)}% match
                    </span>
                  )}
                </div>

                {course.skills_covered && course.skills_covered.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-gray-500 mb-2">Skills covered:</p>
                    <div className="flex flex-wrap gap-1">
                      {course.skills_covered.slice(0, 4).map((skill, index) => (
                        <span
                          key={index}
                          className="inline-flex items-center px-2 py-1 rounded text-xs bg-primary-100 text-primary-800"
                        >
                          {skill}
                        </span>
                      ))}
                      {course.skills_covered.length > 4 && (
                        <span className="text-xs text-gray-500">
                          +{course.skills_covered.length - 4} more
                        </span>
                      )}
                    </div>
                  </div>
                )}

                <div className="flex gap-2">
                  <a
                    href={course.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-primary flex-1 text-center inline-flex items-center justify-center"
                  >
                    <span>Enroll Now</span>
                    <ArrowTopRightOnSquareIcon className="w-4 h-4 ml-2" />
                  </a>
                  
                  <button className="btn btn-outline px-3">
                    <PlayIcon className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Learning Path */}
      {skills.length > 0 && (
        <div className="card">
          <div className="card-body">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <CheckBadgeIcon className="w-5 h-5 text-primary-600 mr-2" />
              Suggested Learning Path
            </h3>
            
            <div className="space-y-3">
              {skills.slice(0, 5).map((skill, index) => (
                <div key={index} className="flex items-center gap-3">
                  <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-600 font-medium text-sm">
                    {index + 1}
                  </div>
                  <div className="flex-1">
                    <p className="font-medium text-gray-900">{skill}</p>
                    <p className="text-sm text-gray-600">
                      {sortedRecommendations.filter(course => 
                        course.skills_covered?.includes(skill)
                      ).length} course{sortedRecommendations.filter(course => 
                        course.skills_covered?.includes(skill)
                      ).length !== 1 ? 's' : ''} available
                    </p>
                  </div>
                  {index < skills.length - 1 && (
                    <div className="w-px h-8 bg-gray-200 ml-4"></div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CourseRecommendations;
