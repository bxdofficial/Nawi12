"""
Nawi Admin Dashboard - Main Application
"""

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

from config import config
from models import db, init_default_roles_and_permissions, User, Role, MediaFile, ActivityLog, SiteSettings, Page, Backup
from utils.auth import (
    require_auth, require_permission, require_role,
    create_tokens, verify_google_token, get_google_oauth_url,
    exchange_google_code, authenticate_with_google,
    validate_password, log_activity, revoke_user_sessions
)

# Import blueprints
from routes.auth import auth_bp
from routes.users import users_bp
from routes.media import media_bp
from routes.pages import pages_bp
from routes.settings import settings_bp
from routes.activity import activity_bp
from routes.backup import backup_bp
from routes.dashboard import dashboard_bp


def create_app(config_name=None):
    """Application factory"""
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.environ.get('FLASK_CONFIG', 'development')
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    # Initialize extensions
    db.init_app(app)
    
    # Initialize JWT
    jwt = JWTManager(app)
    
    # Initialize CORS
    CORS(app, 
         origins=app.config['CORS_ORIGINS'],
         allow_credentials=app.config['CORS_ALLOW_CREDENTIALS'],
         expose_headers=app.config['CORS_EXPOSED_HEADERS'])
    
    # Initialize rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[app.config['RATELIMIT_DEFAULT']],
        enabled=app.config['RATELIMIT_ENABLED']
    )
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(media_bp, url_prefix='/api/media')
    app.register_blueprint(pages_bp, url_prefix='/api/pages')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
    app.register_blueprint(activity_bp, url_prefix='/api/activity')
    app.register_blueprint(backup_bp, url_prefix='/api/backup')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    
    # Create database tables and initialize data
    with app.app_context():
        db.create_all()
        init_default_roles_and_permissions()
        create_default_admin()
        init_default_settings()
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(e):
        log_activity(action='bad_request', error_message=str(e), status_code=400)
        return jsonify({'error': 'Bad request'}), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        log_activity(action='unauthorized', error_message=str(e), status_code=401)
        return jsonify({'error': 'Unauthorized'}), 401
    
    @app.errorhandler(403)
    def forbidden(e):
        log_activity(action='forbidden', error_message=str(e), status_code=403)
        return jsonify({'error': 'Forbidden'}), 403
    
    @app.errorhandler(404)
    def not_found(e):
        log_activity(action='not_found', error_message=str(e), status_code=404)
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        log_activity(action='internal_error', error_message=str(e), status_code=500)
        db.session.rollback()
        return jsonify({'error': 'Internal server error'}), 500
    
    # Health check endpoint
    @app.route('/api/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # Static file serving (for uploaded media)
    @app.route('/uploads/<path:filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    return app


def create_default_admin():
    """Create default admin user if it doesn't exist"""
    admin_email = os.environ.get('ADMIN_EMAIL', 'nawycompany@gmail.com')
    admin_user = User.query.filter_by(email=admin_email).first()
    
    if not admin_user:
        # Create admin user
        admin_user = User(
            email=admin_email,
            username='admin',
            full_name='System Administrator',
            is_active=True,
            is_verified=True,
            email_verified_at=datetime.utcnow()
        )
        
        # Set a secure default password (should be changed on first login)
        temp_password = os.environ.get('ADMIN_PASSWORD', 'ChangeMe123!')
        admin_user.set_password(temp_password)
        
        db.session.add(admin_user)
        db.session.flush()
        
        # Assign admin role
        admin_role = Role.query.filter_by(name='admin').first()
        if admin_role:
            admin_user.add_role(admin_role)
        
        db.session.commit()
        print(f"Default admin created: {admin_email}")
        print(f"Temporary password: {temp_password}")
        print("Please change the password after first login!")


def init_default_settings():
    """Initialize default site settings"""
    default_settings = [
        ('site_title', 'Nawi Creative Studio', 'general', 'string', 'Site title', True),
        ('site_description', 'Professional design and development services', 'general', 'string', 'Site description', True),
        ('site_logo', '/logo.png', 'general', 'string', 'Site logo URL', True),
        ('contact_email', 'contact@nawi.com', 'general', 'string', 'Contact email', True),
        ('maintenance_mode', 'false', 'general', 'boolean', 'Maintenance mode', False),
        ('registration_enabled', 'true', 'security', 'boolean', 'Allow new registrations', False),
        ('google_oauth_enabled', 'true', 'security', 'boolean', 'Enable Google OAuth', False),
        ('email_verification_required', 'true', 'security', 'boolean', 'Require email verification', False),
        ('max_upload_size', '104857600', 'storage', 'number', 'Maximum upload size in bytes', False),
        ('allowed_file_types', 'jpg,jpeg,png,gif,mp4,pdf,doc,docx', 'storage', 'string', 'Allowed file extensions', False),
        ('items_per_page', '20', 'general', 'number', 'Default items per page', False),
        ('enable_analytics', 'true', 'general', 'boolean', 'Enable analytics tracking', False),
        ('backup_retention_days', '30', 'backup', 'number', 'Days to retain backups', False),
        ('log_retention_days', '90', 'logging', 'number', 'Days to retain activity logs', False),
    ]
    
    for key, value, category, value_type, description, is_public in default_settings:
        setting = SiteSettings.query.filter_by(key=key).first()
        if not setting:
            setting = SiteSettings(
                key=key,
                value=value,
                category=category,
                value_type=value_type,
                description=description,
                is_public=is_public
            )
            db.session.add(setting)
    
    db.session.commit()


# Create Flask application
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='localhost', port=port, debug=app.config['DEBUG'])