#!/bin/bash

# Nawi Website Build Script
# This script builds the React frontend and prepares it for Flask deployment

echo "🚀 Starting Nawi Website Build Process..."

# Navigate to frontend directory
cd frontend

# Install dependencies
echo "📦 Installing frontend dependencies..."
npm install

# Build the React app
echo "🔨 Building React application..."
npm run build

# The build will be output to backend/build as configured in vite.config.js

echo "✅ Build complete! The application is ready for deployment."
echo "📁 Build output location: backend/build/"

# Create .env file from example if it doesn't exist
if [ ! -f ../backend/.env ]; then
    echo "📝 Creating .env file from example..."
    cp ../backend/.env.example ../backend/.env
    echo "⚠️  Please update backend/.env with your configuration values!"
fi

echo "✨ Build process finished successfully!"