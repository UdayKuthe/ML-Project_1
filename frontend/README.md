# Skill Gap Analyzer - Frontend

A modern React application built with Tailwind CSS for the Skill Gap Analyzer platform.

## 🚀 Features

- **Modern UI**: Built with React 18 and Tailwind CSS
- **Authentication**: Complete login/register flow with JWT tokens
- **Responsive Design**: Mobile-first responsive design
- **Real-time Updates**: React Query for efficient data fetching
- **Interactive Charts**: Chart.js integration for data visualization
- **File Upload**: Resume upload with drag-and-drop support
- **Form Validation**: Real-time form validation with helpful feedback
- **Toast Notifications**: User-friendly notifications with react-hot-toast

## 🛠️ Tech Stack

- **React 18** - Modern React with hooks
- **Tailwind CSS** - Utility-first CSS framework
- **React Router** - Client-side routing
- **React Query** - Server state management
- **Axios** - HTTP client for API calls
- **Heroicons** - Beautiful SVG icons
- **Chart.js** - Interactive charts and graphs
- **React Dropzone** - File upload component
- **React Hot Toast** - Toast notifications
- **Headless UI** - Unstyled accessible components

## 📦 Installation

### Prerequisites
- Node.js 16.x or higher
- npm or yarn

### Setup Steps

1. **Navigate to frontend directory**
   ```bash
   cd frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   # Create .env file (optional)
   echo "REACT_APP_API_URL=http://localhost:8000/api/v1" > .env
   ```

4. **Start development server**
   ```bash
   npm start
   ```

The application will be available at http://localhost:3000

## 🏗️ Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── auth/           # Authentication components
│   ├── common/         # Common UI components
│   ├── dashboard/      # Dashboard components
│   ├── resume/         # Resume management components
│   ├── analysis/       # Analysis components
│   └── recommendations/ # Course recommendation components
├── pages/              # Page components
├── services/           # API services and utilities
├── context/            # React context providers
├── hooks/              # Custom React hooks
├── utils/              # Utility functions
├── assets/             # Static assets
└── styles/             # Global styles
```

## 🎨 Styling

This project uses Tailwind CSS for styling with:

- **Custom Design System**: Extended Tailwind config with brand colors
- **Component Classes**: Custom CSS components for common patterns
- **Responsive Design**: Mobile-first approach
- **Dark Mode Ready**: Prepared for dark mode implementation

### Key Tailwind Customizations

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: { /* Custom blue palette */ },
        secondary: { /* Custom pink palette */ },
        success: { /* Custom green palette */ },
        warning: { /* Custom amber palette */ },
        error: { /* Custom red palette */ },
      },
      fontFamily: {
        sans: ['Inter', /* system fonts */],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
      },
    },
  },
}
```

## 🔗 API Integration

The frontend communicates with the FastAPI backend through:

- **Axios HTTP Client**: Configured with interceptors for auth
- **React Query**: Caching and synchronization
- **Auto Token Refresh**: Handles JWT token renewal
- **Error Handling**: Global error handling and user feedback

### API Service Structure

```javascript
// services/api.js
export const authAPI = {
  login: (email, password) => { /* ... */ },
  register: (userData) => { /* ... */ },
  // ...
};

export const resumeAPI = {
  upload: (file) => { /* ... */ },
  getAll: (params) => { /* ... */ },
  // ...
};
```

## 🔐 Authentication

The authentication system includes:

- **JWT Token Management**: Automatic token storage and refresh
- **Protected Routes**: Route-level authentication guards
- **Context Provider**: Global authentication state
- **Form Validation**: Real-time validation with helpful feedback

### Authentication Flow

1. User submits login/register form
2. API returns JWT tokens (access + refresh)
3. Tokens stored in localStorage
4. Auto-refresh on token expiration
5. Redirect to protected routes

## 📊 State Management

- **React Context**: Authentication and global state
- **React Query**: Server state and caching
- **Local State**: Component-level state with useState
- **Form State**: Form handling with controlled components

## 🎯 Key Components

### Authentication Components
- `LoginForm` - User login with validation
- `RegisterForm` - User registration with password strength
- `ProtectedRoute` - Route protection wrapper

### Common Components
- `Layout` - Main application layout with sidebar
- `LoadingSpinner` - Reusable loading indicator
- `Button` - Customizable button component
- `Input` - Form input with validation

### Dashboard Components
- `DashboardPage` - Main dashboard with stats and recent activity
- `StatsCard` - Metric display cards
- `QuickActions` - Action shortcuts

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 🏗️ Build

```bash
# Create production build
npm run build

# Preview production build locally
npx serve -s build
```

## 📱 Responsive Design

The application is fully responsive with:

- **Mobile First**: Designed for mobile, enhanced for desktop
- **Breakpoints**: sm, md, lg, xl breakpoints
- **Flexible Layout**: CSS Grid and Flexbox layouts
- **Touch Friendly**: Large touch targets for mobile

### Responsive Features
- Collapsible sidebar on mobile
- Stack layouts on small screens
- Optimized navigation for touch
- Readable typography at all sizes

## 🎨 Design System

### Colors
- **Primary**: Blue tones for main actions
- **Secondary**: Pink/purple for accents
- **Success**: Green for positive actions
- **Warning**: Amber for cautions
- **Error**: Red for errors

### Typography
- **Font**: Inter (system fallback)
- **Scale**: Modular scale with good hierarchy
- **Weight**: 300-700 font weights

### Components
- **Cards**: Elevated panels with consistent styling
- **Buttons**: Multiple variants (primary, secondary, outline)
- **Forms**: Consistent form styling with validation states
- **Navigation**: Clean navigation with active states

## 🚀 Deployment

### Environment Variables
```bash
# Production API URL
REACT_APP_API_URL=https://api.yourdomain.com/api/v1

# Optional: Analytics ID
REACT_APP_GA_ID=GA-XXXXXXXXX
```

### Build and Deploy
```bash
# Build for production
npm run build

# Deploy to static hosting (Netlify, Vercel, etc.)
# Upload the build/ folder contents
```

## 🔧 Development

### Available Scripts
- `npm start` - Start development server
- `npm test` - Run test suite
- `npm run build` - Create production build
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint errors
- `npm run format` - Format code with Prettier

### Code Style
- **ESLint**: JavaScript/React linting
- **Prettier**: Code formatting
- **Conventions**: Functional components with hooks
- **File Naming**: PascalCase for components, camelCase for utilities

## 🤝 Contributing

1. Follow the existing code style and conventions
2. Write tests for new features
3. Update documentation for API changes
4. Use meaningful commit messages
5. Create pull requests for review

## 🐛 Troubleshooting

### Common Issues

**Build Errors**
```bash
# Clear node modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

**CORS Issues**
```javascript
// Update proxy in package.json or use .env
"proxy": "http://localhost:8000"
```

**Styling Issues**
```bash
# Rebuild Tailwind CSS
npm run build:css
```

### Getting Help
- Check the browser console for errors
- Verify API endpoints are accessible
- Ensure backend server is running
- Check network requests in browser dev tools

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🎉 Happy Coding!** The Skill Gap Analyzer frontend is ready to provide an amazing user experience!
