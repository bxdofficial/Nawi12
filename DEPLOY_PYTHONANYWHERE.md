# PythonAnywhere Deployment Guide for Nawi Website

This guide provides step-by-step instructions for deploying the Nawi website to PythonAnywhere.

## 📋 Pre-Deployment Checklist

- [ ] PythonAnywhere account created
- [ ] Project files ready (backend + built frontend)
- [ ] Gmail app password generated for email
- [ ] Production secret keys generated

## 🚀 Step-by-Step Deployment

### Step 1: Prepare Your Files Locally

1. **Build the React frontend**:
```bash
cd frontend
npm install
npm run build
```
This creates the `backend/build` directory with production files.

2. **Create production `.env`**:
```bash
cd backend
cp .env.example .env.production
```

Edit `.env.production` with secure values:
```env
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=<generate-secure-64-char-key>
JWT_SECRET_KEY=<generate-another-secure-64-char-key>
DATABASE_URL=sqlite:///nawi.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=nawycompany@gmail.com
MAIL_PASSWORD=<gmail-app-specific-password>
MAIL_DEFAULT_SENDER=nawycompany@gmail.com
ADMIN_EMAIL=nawycompany@gmail.com
ADMIN_PASSWORD=<secure-admin-password>
```

### Step 2: Upload to PythonAnywhere

1. **Create ZIP archive** (excluding unnecessary files):
```bash
# From project root
zip -r nawi-deploy.zip . \
  -x "*.git*" \
  -x "*node_modules*" \
  -x "*venv*" \
  -x "*__pycache__*" \
  -x "*.pyc" \
  -x "frontend/src*" \
  -x "frontend/public*" \
  -x "*.DS_Store"
```

2. **Upload via PythonAnywhere Files tab**:
   - Go to Files tab in PythonAnywhere
   - Navigate to your home directory
   - Upload `nawi-deploy.zip`
   - Open Bash console and extract:
```bash
unzip nawi-deploy.zip -d nawi-website
cd nawi-website/backend
mv .env.production .env
```

### Step 3: Set Up Virtual Environment

In PythonAnywhere Bash console:
```bash
# Create virtual environment
mkvirtualenv --python=/usr/bin/python3.10 nawi-env

# Install dependencies
cd ~/nawi-website/backend
pip install -r requirements.txt
```

### Step 4: Configure Web App

1. **Go to Web tab** → "Add a new web app"
2. Select "Manual configuration" (not Flask)
3. Choose Python 3.10

### Step 5: Configure WSGI

Edit the WSGI configuration file (click on the link in Web tab):

```python
# +++++++++++ NAWI WEBSITE WSGI +++++++++++
import sys
import os
from pathlib import Path

# Add project paths
project_home = '/home/YOUR_USERNAME/nawi-website/backend'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variables from .env file
from dotenv import load_dotenv
env_path = os.path.join(project_home, '.env')
load_dotenv(env_path)

# Import Flask app
from app import app as application
from app import init_db

# Initialize database on first run
with application.app_context():
    try:
        init_db()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

# Enable debugging (remove in production)
application.debug = False
```

### Step 6: Configure Static Files

In the Web tab, set up static file mappings:

| URL | Directory |
|-----|-----------|
| `/static/` | `/home/YOUR_USERNAME/nawi-website/backend/static` |
| `/assets/` | `/home/YOUR_USERNAME/nawi-website/backend/build/assets` |
| `/` | `/home/YOUR_USERNAME/nawi-website/backend/build` |

### Step 7: Configure Virtual Environment

In Web tab → "Virtualenv" section:
- Enter: `/home/YOUR_USERNAME/.virtualenvs/nawi-env`

### Step 8: Additional Settings

1. **Force HTTPS** (in Web tab):
   - Enable "Force HTTPS" option

2. **Set working directory**:
   - `/home/YOUR_USERNAME/nawi-website/backend`

### Step 9: Create Upload Directory

In Bash console:
```bash
cd ~/nawi-website/backend
mkdir -p static/uploads
chmod 755 static/uploads
```

### Step 10: Initialize Database

In PythonAnywhere Bash console:
```bash
cd ~/nawi-website/backend
python
```

```python
from app import app, db, init_db
with app.app_context():
    db.create_all()
    init_db()
exit()
```

### Step 11: Reload Web App

Click the green "Reload" button in the Web tab.

## 🔍 Testing Your Deployment

1. **Visit your site**: `https://YOUR_USERNAME.pythonanywhere.com`
2. **Test key features**:
   - [ ] Homepage loads with animations
   - [ ] Portfolio gallery works
   - [ ] Contact form submission
   - [ ] Admin login (`/login`)
   - [ ] User registration

## 🐛 Troubleshooting

### Error Logs
Check error logs in Web tab → "Log files" → Error log

### Common Issues and Solutions

#### 1. Import Error
```
Error: No module named 'app'
```
**Solution**: Check WSGI file paths and ensure project_home is correct

#### 2. Static Files Not Loading
**Solution**: Verify static file mappings in Web tab match your directory structure

#### 3. Database Error
```
Error: No such table: user
```
**Solution**: Run database initialization:
```bash
cd ~/nawi-website/backend
python -c "from app import app, init_db; app.app_context().push(); init_db()"
```

#### 4. Email Not Sending
**Solution**: 
- Verify Gmail app password in `.env`
- Check if PythonAnywhere account has email privileges (free accounts have limitations)

#### 5. 500 Internal Server Error
**Solution**: 
- Check error logs
- Verify all dependencies are installed
- Ensure `.env` file exists and is properly configured

### File Permissions
```bash
# Fix permissions if needed
cd ~/nawi-website
chmod 755 backend
chmod 755 backend/static
chmod 755 backend/static/uploads
chmod 644 backend/.env
```

## 📊 Performance Optimization

1. **Enable Gzip compression** (automatically enabled on PythonAnywhere)

2. **Set appropriate cache headers** in `app.py`:
```python
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response
```

3. **Database optimization**:
   - Consider upgrading to MySQL for better performance
   - Add database indexes for frequently queried fields

## 🔄 Updating Your Site

1. **Make changes locally and test**
2. **Build frontend**: `npm run build`
3. **Upload changed files** via Files tab
4. **Reload web app** in Web tab

### Using Git for Updates

Set up Git in PythonAnywhere:
```bash
cd ~/nawi-website
git init
git remote add origin https://github.com/YOUR_USERNAME/nawi-website.git
git pull origin main
```

Future updates:
```bash
cd ~/nawi-website
git pull origin main
cd frontend && npm install && npm run build
# Reload web app in Web tab
```

## 📈 Monitoring

1. **Check CPU seconds** used (in Account tab)
2. **Monitor error logs** regularly
3. **Set up uptime monitoring** (e.g., UptimeRobot)

## 🔒 Security Recommendations

1. **Change default passwords immediately**
2. **Use strong secret keys** (generate with `python -c "import secrets; print(secrets.token_hex(32))"`)
3. **Regularly update dependencies**
4. **Enable HTTPS** (already forced in Web tab)
5. **Backup database regularly**:
```bash
cd ~/nawi-website/backend
cp nawi.db nawi_backup_$(date +%Y%m%d).db
```

## 💡 Free Account Limitations

PythonAnywhere free accounts have:
- 512 MB disk space
- Limited CPU seconds/day
- No outbound internet (except whitelisted sites)
- One web app
- Sleeps after 3 months of inactivity

For production use, consider upgrading to a paid plan.

## 📞 Support

- **PythonAnywhere Forums**: https://www.pythonanywhere.com/forums/
- **Nawi Support**: nawycompany@gmail.com
- **Documentation**: https://help.pythonanywhere.com/

---

Last updated: 2024
Version: 1.0