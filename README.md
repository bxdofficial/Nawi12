# Nawi - ناوي | Creative Design Studio Website

A fully interactive, professional company website for Nawi Design Studio built with Flask (Python) backend and React frontend, featuring stunning animations and a complete admin system.

![Nawi Logo](frontend/public/logo.png)

## 🌟 Features

### 🎨 Design & User Experience
- **Futuristic Interactive Design**: Sky blue and neon purple gradients with glowing effects
- **Animated Backgrounds**: Particle effects, gradient animations, and soft glows
- **Framer Motion Animations**: Smooth transitions, scroll-triggered animations, and hover effects
- **Fully Responsive**: Optimized for desktop, tablet, and mobile devices
- **Arabic & English Support**: Bilingual content throughout the website

### 📱 Core Functionality
- **Portfolio Gallery**: Dynamic gallery with category filtering and lightbox viewer
- **Service Showcase**: Interactive service cards with detailed information
- **Contact System**: Animated contact form with email notifications
- **Design Request System**: Clients can request design services directly
- **User Authentication**: JWT-based authentication for secure access
- **Client Dashboard**: Track design requests and download completed designs
- **Admin Dashboard**: Full CRUD operations for managing content and requests

### 🛠️ Technical Features
- **Flask Backend**: RESTful API with SQLAlchemy ORM
- **React Frontend**: Modern React with hooks and context API
- **Database**: SQLite (easily upgradable to PostgreSQL)
- **Email Integration**: Automated email notifications for requests and contact forms
- **File Upload**: Support for portfolio images and design files
- **Role-Based Access**: Separate admin and client functionalities

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/nawi-website.git
cd nawi-website
```

2. **Backend Setup**
```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env

# Update .env with your configuration
# Edit the following in .env:
# - SECRET_KEY: Generate a secure secret key
# - JWT_SECRET_KEY: Generate another secure key
# - MAIL_USERNAME: Your Gmail address
# - MAIL_PASSWORD: Your Gmail app-specific password
# - ADMIN_EMAIL: Admin email address
# - ADMIN_PASSWORD: Admin login password
```

3. **Frontend Setup**
```bash
# Navigate to frontend directory
cd ../frontend

# Install dependencies
npm install
```

4. **Build the Application**
```bash
# From the root directory
chmod +x build.sh
./build.sh
```

## 🏃‍♂️ Running Locally

### Development Mode

1. **Start the Flask backend**
```bash
cd backend
python app.py
```
The backend will run on http://localhost:5000

2. **Start the React frontend** (in a new terminal)
```bash
cd frontend
npm run dev
```
The frontend will run on http://localhost:3000

### Production Mode

After building with `./build.sh`, run:
```bash
cd backend
python app.py
```
Access the full application at http://localhost:5000

## 📧 Email Configuration

To enable email functionality:

1. **Gmail Setup**:
   - Enable 2-factor authentication on your Gmail account
   - Generate an app-specific password
   - Add credentials to `.env` file

2. **Alternative Email Providers**:
   - Update `MAIL_SERVER` and `MAIL_PORT` in `.env`
   - Adjust TLS/SSL settings as needed

## 🌐 Deployment on PythonAnywhere

### 1. Create PythonAnywhere Account
- Sign up at [PythonAnywhere](https://www.pythonanywhere.com)
- Choose a username (this will be part of your URL)

### 2. Upload Files
```bash
# Option 1: Using Git
# In PythonAnywhere Bash console:
git clone https://github.com/yourusername/nawi-website.git

# Option 2: Upload ZIP
# Upload your project ZIP and extract:
unzip nawi-website.zip
```

### 3. Setup Virtual Environment
```bash
# In PythonAnywhere Bash console
mkvirtualenv --python=/usr/bin/python3.10 nawienv
pip install -r /home/yourusername/nawi-website/backend/requirements.txt
```

### 4. Configure Web App
1. Go to Web tab in PythonAnywhere dashboard
2. Create new web app
3. Choose "Manual configuration" and Python 3.10
4. Configure:
   - **Source code**: `/home/yourusername/nawi-website/backend`
   - **Working directory**: `/home/yourusername/nawi-website/backend`
   - **WSGI file**: Edit and replace content with:
```python
import sys
import os

# Add your project directory to the sys.path
project_home = '/home/yourusername/nawi-website/backend'
if project_home not in sys.path:
    sys.path = [project_home] + sys.path

# Import Flask app
from app import app as application
from app import init_db

# Initialize database
with application.app_context():
    init_db()
```

### 5. Static Files Configuration
In PythonAnywhere Web tab, set static files:
- URL: `/static/`
- Directory: `/home/yourusername/nawi-website/backend/static`
- URL: `/` 
- Directory: `/home/yourusername/nawi-website/backend/build`

### 6. Environment Variables
Create `/home/yourusername/nawi-website/backend/.env` with production values

### 7. Reload Web App
Click "Reload" button in Web tab

Your site will be live at: `https://yourusername.pythonanywhere.com`

## 📂 Project Structure

```
nawi-website/
├── backend/
│   ├── api/              # API endpoints
│   ├── models/           # Database models
│   ├── utils/            # Utility functions
│   ├── static/           # Static files and uploads
│   ├── build/            # React build output
│   ├── app.py            # Main Flask application
│   ├── config.py         # Configuration settings
│   ├── wsgi.py           # WSGI entry point
│   └── requirements.txt  # Python dependencies
│
├── frontend/
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   ├── contexts/     # React contexts
│   │   ├── utils/        # Utility functions
│   │   └── assets/       # Images and assets
│   ├── public/           # Public assets
│   ├── package.json      # Node dependencies
│   └── vite.config.js    # Vite configuration
│
├── build.sh              # Build script
└── README.md             # This file
```

## 🔑 Default Credentials

**Admin Access:**
- Email: nawycompany@gmail.com
- Password: admin123 (Change this immediately!)

## 🎨 Customization

### Changing Colors
Edit `frontend/tailwind.config.js`:
```javascript
colors: {
  'nawi-blue': '#3B82F6',
  'nawi-purple': '#5B21B6',
  // Add your colors here
}
```

### Adding Services
Services can be added through the Admin Dashboard or by modifying the seed data in `backend/app.py`

### Updating Contact Information
Update contact details in:
- `frontend/src/components/layout/Footer.jsx`
- `frontend/src/pages/Contact.jsx`
- Backend `.env` file

## 🔧 Troubleshooting

### Common Issues

1. **Database errors**: 
   - Delete `backend/nawi.db` and restart the app to recreate

2. **Email not sending**:
   - Check Gmail app-specific password
   - Ensure less secure app access is enabled
   - Verify SMTP settings in `.env`

3. **Build fails**:
   - Clear npm cache: `npm cache clean --force`
   - Delete `node_modules` and reinstall

4. **PythonAnywhere import errors**:
   - Verify virtual environment is activated
   - Check sys.path in WSGI file

## 📱 Contact & Support

**Nawi Company**
- 📧 Email: nawycompany@gmail.com
- 📞 Phone: +20 120 631 5886
- 💬 WhatsApp: +201206315886

## 📄 License

This project is proprietary software created for Nawi Design Studio.

## 🙏 Acknowledgments

- React & Vite for the amazing frontend framework
- Flask for the robust backend
- Framer Motion for beautiful animations
- TailwindCSS for utility-first styling
- The Nawi team for their creative vision

---

Built with ❤️ by Nawi - ناوي | فريق التصميم اللي بيحوّل فكرتك لهوية