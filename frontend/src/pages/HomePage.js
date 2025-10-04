import React from 'react';
import { Link } from 'react-router-dom';
import { 
  ArrowRightIcon, 
  CheckIcon,
  ChartBarIcon,
  DocumentTextIcon,
  AcademicCapIcon,
  UserGroupIcon,
  StarIcon,
  PlayCircleIcon
} from '@heroicons/react/24/outline';

const HomePage = () => {
  const features = [
    {
      name: 'Resume Analysis',
      description: 'Upload your resume and get instant skill extraction with AI-powered NLP technology.',
      icon: DocumentTextIcon,
    },
    {
      name: 'Gap Analysis',
      description: 'Compare your skills against job requirements and identify areas for improvement.',
      icon: ChartBarIcon,
    },
    {
      name: 'Course Recommendations',
      description: 'Get personalized learning recommendations from top platforms to bridge skill gaps.',
      icon: AcademicCapIcon,
    },
    {
      name: 'Career Insights',
      description: 'Access data-driven insights about trending skills and industry demands.',
      icon: UserGroupIcon,
    },
  ];

  const testimonials = [
    {
      name: 'Sarah Johnson',
      role: 'Software Developer',
      content: 'This tool helped me identify the exact skills I needed for my dream job. Got hired within 2 months!',
      rating: 5,
    },
    {
      name: 'Michael Chen',
      role: 'Data Analyst',
      content: 'The course recommendations were spot-on. I could focus my learning on what really mattered.',
      rating: 5,
    },
    {
      name: 'Emily Davis',
      role: 'UX Designer',
      content: 'Amazing insights into market trends. Helped me stay ahead of the curve in my field.',
      rating: 5,
    },
  ];

  const stats = [
    { name: 'Resumes Analyzed', value: '10,000+' },
    { name: 'Skills Identified', value: '50,000+' },
    { name: 'Courses Recommended', value: '25,000+' },
    { name: 'Career Success Rate', value: '87%' },
  ];

  return (
    <div className="bg-white">
      {/* Navigation */}
      <nav className="relative max-w-7xl mx-auto flex items-center justify-between px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center">
          <div className="h-8 w-8 bg-primary-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-sm">SGA</span>
          </div>
          <span className="ml-2 text-xl font-bold text-gray-900">
            Skill Gap Analyzer
          </span>
        </div>
        <div className="flex items-center space-x-4">
          <Link
            to="/login"
            className="text-gray-600 hover:text-gray-900 font-medium"
          >
            Sign in
          </Link>
          <Link
            to="/register"
            className="btn btn-primary"
          >
            Get Started
          </Link>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 text-center">
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-gray-900 leading-tight">
            Bridge Your{' '}
            <span className="text-gradient">Skill Gaps</span>
            <br />
            with AI-Powered Insights
          </h1>
          <p className="mt-6 max-w-3xl mx-auto text-xl text-gray-600 leading-8">
            Analyze your resume, identify skill gaps against job requirements, and get personalized 
            course recommendations to advance your career with confidence.
          </p>
          <div className="mt-10 flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/register"
              className="btn btn-primary btn-lg inline-flex items-center"
            >
              Start Free Analysis
              <ArrowRightIcon className="ml-2 h-5 w-5" />
            </Link>
            <button className="btn btn-outline btn-lg inline-flex items-center">
              <PlayCircleIcon className="mr-2 h-5 w-5" />
              Watch Demo
            </button>
          </div>

          {/* Trust Indicators */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat) => (
              <div key={stat.name} className="text-center">
                <div className="text-3xl font-bold text-primary-600">{stat.value}</div>
                <div className="text-sm text-gray-600 mt-1">{stat.name}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
              Everything you need to advance your career
            </h2>
            <p className="mt-4 text-lg text-gray-600 max-w-3xl mx-auto">
              Our AI-powered platform provides comprehensive skill analysis and personalized 
              recommendations to help you achieve your career goals.
            </p>
          </div>

          <div className="mt-20 grid grid-cols-1 gap-12 sm:grid-cols-2 lg:grid-cols-4">
            {features.map((feature) => (
              <div key={feature.name} className="text-center">
                <div className="flex items-center justify-center h-16 w-16 rounded-xl bg-primary-100 mx-auto">
                  <feature.icon className="h-8 w-8 text-primary-600" />
                </div>
                <h3 className="mt-6 text-lg font-semibold text-gray-900">{feature.name}</h3>
                <p className="mt-2 text-gray-600">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it Works Section */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
              How it works
            </h2>
            <p className="mt-4 text-lg text-gray-600">
              Get career insights in three simple steps
            </p>
          </div>

          <div className="mt-20 grid grid-cols-1 gap-12 lg:grid-cols-3">
            <div className="text-center">
              <div className="flex items-center justify-center h-16 w-16 rounded-full bg-primary-600 text-white text-xl font-bold mx-auto">
                1
              </div>
              <h3 className="mt-6 text-xl font-semibold text-gray-900">Upload Your Resume</h3>
              <p className="mt-4 text-gray-600">
                Simply upload your resume in PDF or Word format. Our AI will extract and analyze 
                your skills automatically.
              </p>
            </div>

            <div className="text-center">
              <div className="flex items-center justify-center h-16 w-16 rounded-full bg-primary-600 text-white text-xl font-bold mx-auto">
                2
              </div>
              <h3 className="mt-6 text-xl font-semibold text-gray-900">Choose Target Role</h3>
              <p className="mt-4 text-gray-600">
                Select the job role you're targeting. We'll compare your skills against 
                industry requirements and identify gaps.
              </p>
            </div>

            <div className="text-center">
              <div className="flex items-center justify-center h-16 w-16 rounded-full bg-primary-600 text-white text-xl font-bold mx-auto">
                3
              </div>
              <h3 className="mt-6 text-xl font-semibold text-gray-900">Get Recommendations</h3>
              <p className="mt-4 text-gray-600">
                Receive personalized course recommendations and learning paths to bridge 
                your skill gaps effectively.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-24 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
              Loved by professionals worldwide
            </h2>
            <p className="mt-4 text-lg text-gray-600">
              See what our users say about their experience
            </p>
          </div>

          <div className="mt-20 grid grid-cols-1 gap-8 lg:grid-cols-3">
            {testimonials.map((testimonial, index) => (
              <div key={index} className="card">
                <div className="card-body">
                  <div className="flex items-center space-x-1 mb-4">
                    {[...Array(testimonial.rating)].map((_, i) => (
                      <StarIcon key={i} className="h-5 w-5 text-yellow-400 fill-current" />
                    ))}
                  </div>
                  <p className="text-gray-600 mb-4">"{testimonial.content}"</p>
                  <div>
                    <div className="font-semibold text-gray-900">{testimonial.name}</div>
                    <div className="text-sm text-gray-500">{testimonial.role}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl">
            Ready to advance your career?
          </h2>
          <p className="mt-4 text-lg text-gray-600 max-w-2xl mx-auto">
            Join thousands of professionals who have successfully bridged their skill gaps 
            and achieved their career goals with our AI-powered platform.
          </p>
          <div className="mt-10">
            <Link
              to="/register"
              className="btn btn-primary btn-lg inline-flex items-center"
            >
              Get Started for Free
              <ArrowRightIcon className="ml-2 h-5 w-5" />
            </Link>
          </div>
          <p className="mt-4 text-sm text-gray-500">
            No credit card required • Free analysis • Instant results
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="col-span-1">
              <div className="flex items-center">
                <div className="h-8 w-8 bg-primary-600 rounded-lg flex items-center justify-center">
                  <span className="text-white font-bold text-sm">SGA</span>
                </div>
                <span className="ml-2 text-xl font-bold text-white">
                  Skill Gap Analyzer
                </span>
              </div>
              <p className="mt-4 text-gray-300">
                Empowering careers with AI-driven skill analysis and personalized learning recommendations.
              </p>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">Product</h3>
              <ul className="mt-4 space-y-4">
                <li><Link to="/features" className="text-gray-300 hover:text-white">Features</Link></li>
                <li><Link to="/pricing" className="text-gray-300 hover:text-white">Pricing</Link></li>
                <li><Link to="/integrations" className="text-gray-300 hover:text-white">Integrations</Link></li>
              </ul>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">Company</h3>
              <ul className="mt-4 space-y-4">
                <li><Link to="/about" className="text-gray-300 hover:text-white">About</Link></li>
                <li><Link to="/blog" className="text-gray-300 hover:text-white">Blog</Link></li>
                <li><Link to="/careers" className="text-gray-300 hover:text-white">Careers</Link></li>
              </ul>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-gray-400 tracking-wider uppercase">Support</h3>
              <ul className="mt-4 space-y-4">
                <li><Link to="/help" className="text-gray-300 hover:text-white">Help Center</Link></li>
                <li><Link to="/contact" className="text-gray-300 hover:text-white">Contact</Link></li>
                <li><Link to="/privacy" className="text-gray-300 hover:text-white">Privacy</Link></li>
                <li><Link to="/terms" className="text-gray-300 hover:text-white">Terms</Link></li>
              </ul>
            </div>
          </div>

          <div className="mt-8 pt-8 border-t border-gray-700 text-center">
            <p className="text-gray-300">
              © {new Date().getFullYear()} Skill Gap Analyzer. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default HomePage;
