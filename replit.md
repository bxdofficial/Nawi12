# Nawitow - Design Agency Website

## Overview
Nawitow is a professional design agency website featuring a React frontend and Flask backend. The application supports user authentication, portfolio management, service showcasing, and contact/design request functionality with Arabic and English language support.

## Project Architecture
- **Frontend**: React 18 with Vite, Tailwind CSS, Framer Motion
- **Backend**: Flask with SQLAlchemy, JWT authentication, email functionality
- **Database**: PostgreSQL (with SQLite fallback for development)
- **Languages**: JavaScript/React, Python/Flask

## Current Setup (Replit Environment)
- Frontend serves on port 5000 (configured for Replit proxy)
- Backend API runs on port 8000 (localhost only)
- Virtual environment created with uv in `.pythonlibs/`
- Frontend workflow configured and running
- Backend tested and working with API endpoints

## Recent Changes
- **2025-09-24**: Fresh GitHub import and Replit environment setup
  - ✅ Installed Python dependencies using uv (Flask, SQLAlchemy, JWT, etc.)
  - ✅ Installed Node.js dependencies for React frontend
  - ✅ Fixed backend configuration for Replit (port 8000, localhost)
  - ✅ Configured frontend workflow on port 5000 with Replit proxy support
  - ✅ Set up PostgreSQL database connection and initialization
  - ✅ Fixed missing dependencies (flask-limiter, python-magic, libmagic)
  - ✅ Configured CORS to allow frontend-backend communication
  - ✅ Set up deployment configuration for autoscale production deployment
  - ✅ Frontend running successfully on port 5000 with Vite dev server
  - ✅ Backend initializes properly with database setup and admin user creation

- **Previous Versions**: Enhanced admin functionality and user management
  - Fixed admin login to accept both admin/admin123 and email/password
  - Added comprehensive admin dashboard APIs for design management
  - Enhanced user model with phone, is_teacher, region, governorate fields
  - Implemented organized file upload system (designs/portfolio/profile/general folders)
  - Added production optimizations (caching, performance headers)
  - Verified Arabic/English bilingual support working properly

## Key Features
- Bilingual (Arabic/English) design agency website
- User authentication and registration
- Admin dashboard for managing requests and messages
- Portfolio showcase with categories
- Service listings with pricing
- Contact forms and design request forms
- File upload functionality for designs
- Email notifications system

## Deployment Configuration
- Target: autoscale (stateless web application)
- Build: Runs build.sh script to compile React frontend
- Run: Uses Flask backend to serve both API and static files
- Static files built to backend/build directory for unified serving

## User Preferences
- Project follows existing Flask/React architecture patterns
- Uses uv for Python dependency management
- Maintains Arabic RTL language support
- Professional design agency branding (Nawi/ناوي)