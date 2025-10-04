import axios from 'axios';

// Create axios instance with default config
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (refreshToken) {
          const response = await axios.post(
            `${api.defaults.baseURL}/auth/refresh`,
            { refresh_token: refreshToken }
          );
          
          const { access_token } = response.data;
          localStorage.setItem('token', access_token);
          
          // Retry the original request with new token
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, logout user
        localStorage.removeItem('token');
        localStorage.removeItem('refreshToken');
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

// Authentication API
export const authAPI = {
  login: async (email, password) => {
    const response = await api.post('/auth/login', { email, password });
    return response.data;
  },

  register: async (userData) => {
    const response = await api.post('/auth/register', userData);
    return response.data;
  },

  getProfile: async () => {
    const response = await api.get('/auth/profile');
    return response.data;
  },

  refreshToken: async (refreshToken) => {
    const response = await api.post('/auth/refresh', { refresh_token: refreshToken });
    return response.data;
  },

  logout: async () => {
    const response = await api.post('/auth/logout');
    return response.data;
  },
};

// Resume API
export const resumeAPI = {
  upload: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/resumes/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  getAll: async (params = {}) => {
    const response = await api.get('/resumes', { params });
    return response.data;
  },

  getById: async (resumeId) => {
    const response = await api.get(`/resumes/${resumeId}`);
    return response.data;
  },

  getStatus: async (resumeId) => {
    const response = await api.get(`/resumes/${resumeId}/status`);
    return response.data;
  },

  delete: async (resumeId) => {
    const response = await api.delete(`/resumes/${resumeId}`);
    return response.data;
  },

  reprocess: async (resumeId) => {
    const response = await api.post(`/resumes/${resumeId}/reprocess`);
    return response.data;
  },
};

// Skills and Jobs API
export const skillsJobsAPI = {
  getSkills: async (params = {}) => {
    const response = await api.get('/skills-jobs/skills', { params });
    return response.data;
  },

  searchSkills: async (query, params = {}) => {
    const response = await api.get('/skills-jobs/skills/search', {
      params: { query, ...params },
    });
    return response.data;
  },

  getTrendingSkills: async (params = {}) => {
    const response = await api.get('/skills-jobs/skills/trending', { params });
    return response.data;
  },

  getSkillCategories: async () => {
    const response = await api.get('/skills-jobs/skills/categories');
    return response.data;
  },

  getJobs: async (params = {}) => {
    const response = await api.get('/skills-jobs/jobs', { params });
    return response.data;
  },

  searchJobs: async (query, params = {}) => {
    const response = await api.get('/skills-jobs/jobs/search', {
      params: { query, ...params },
    });
    return response.data;
  },

  getJobById: async (jobId) => {
    const response = await api.get(`/skills-jobs/jobs/${jobId}`);
    return response.data;
  },

  getJobCategories: async () => {
    const response = await api.get('/skills-jobs/jobs/categories');
    return response.data;
  },
};

// Analysis API
export const analysisAPI = {
  analyze: async (resumeId, jobTitle) => {
    const response = await api.post('/analysis/analyze', {
      resume_id: resumeId,
      job_title: jobTitle,
    });
    return response.data;
  },

  getHistory: async (params = {}) => {
    const response = await api.get('/analysis/history', { params });
    return response.data;
  },

  getById: async (analysisId) => {
    const response = await api.get(`/analysis/${analysisId}`);
    return response.data;
  },
};

// Dashboard API
export const dashboardAPI = {
  getStats: async () => {
    const response = await api.get('/dashboard/stats');
    return response.data;
  },

  getRecentAnalyses: async (limit = 5) => {
    const response = await api.get('/dashboard/recent-analyses', {
      params: { limit },
    });
    return response.data;
  },
};

// Course Recommendations API (if separate endpoint exists)
export const courseAPI = {
  getRecommendations: async (skills, params = {}) => {
    const response = await api.post('/courses/recommendations', {
      skills,
      ...params,
    });
    return response.data;
  },

  searchCourses: async (query, params = {}) => {
    const response = await api.get('/courses/search', {
      params: { query, ...params },
    });
    return response.data;
  },
};

// Health Check API
export const healthAPI = {
  check: async () => {
    const response = await api.get('/health');
    return response.data;
  },

  info: async () => {
    const response = await api.get('/info');
    return response.data;
  },
};

// Utility functions
export const uploadProgress = (onProgress) => {
  return {
    onUploadProgress: (progressEvent) => {
      const percentCompleted = Math.round(
        (progressEvent.loaded * 100) / progressEvent.total
      );
      onProgress(percentCompleted);
    },
  };
};

// Error handling utility
export const handleAPIError = (error) => {
  if (error.response) {
    // Server responded with error status
    return {
      message: error.response.data?.detail || error.response.data?.error || 'An error occurred',
      status: error.response.status,
      data: error.response.data,
    };
  } else if (error.request) {
    // Request made but no response received
    return {
      message: 'Network error. Please check your connection.',
      status: null,
      data: null,
    };
  } else {
    // Something else happened
    return {
      message: error.message || 'An unexpected error occurred',
      status: null,
      data: null,
    };
  }
};

// Default export for convenience
export default api;
