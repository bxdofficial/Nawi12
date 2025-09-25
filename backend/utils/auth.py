"""
Authentication utilities including Google OAuth support
"""

import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import current_app, request, jsonify, session
from flask_jwt_extended import (
    create_access_token, create_refresh_token, 
    get_jwt_identity, verify_jwt_in_request
)
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests

from models import db, User, Role, UserSession, ActivityLog


def create_tokens(user):
    """Create access and refresh tokens for a user"""
    # Create identity with user data
    identity = {
        'user_id': user.id,
        'email': user.email,
        'roles': [role.name for role in user.roles]
    }
    
    # Create tokens
    access_token = create_access_token(identity=json.dumps(identity))
    refresh_token = create_refresh_token(identity=json.dumps(identity))
    
    # Create session record
    user_session = UserSession(
        user_id=user.id,
        token=access_token,
        refresh_token=refresh_token,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        expires_at=datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    )
    db.session.add(user_session)
    
    # Update user last login
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
        'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
    }


def verify_google_token(token):
    """Verify Google ID token and return user info"""
    try:
        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(
            token, 
            google_requests.Request(), 
            current_app.config['GOOGLE_CLIENT_ID']
        )
        
        # Verify the issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        # Extract user information
        return {
            'google_id': idinfo['sub'],
            'email': idinfo.get('email'),
            'email_verified': idinfo.get('email_verified', False),
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture'),
            'given_name': idinfo.get('given_name'),
            'family_name': idinfo.get('family_name')
        }
    except Exception as e:
        current_app.logger.error(f"Google token verification failed: {str(e)}")
        return None


def get_google_oauth_url():
    """Generate Google OAuth URL"""
    google_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        'client_id': current_app.config['GOOGLE_CLIENT_ID'],
        'redirect_uri': current_app.config['GOOGLE_REDIRECT_URI'],
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent'
    }
    
    return f"{google_auth_endpoint}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"


def exchange_google_code(code):
    """Exchange authorization code for tokens"""
    token_endpoint = "https://oauth2.googleapis.com/token"
    
    data = {
        'code': code,
        'client_id': current_app.config['GOOGLE_CLIENT_ID'],
        'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri': current_app.config['GOOGLE_REDIRECT_URI'],
        'grant_type': 'authorization_code'
    }
    
    response = requests.post(token_endpoint, data=data)
    if response.status_code == 200:
        return response.json()
    return None


def authenticate_with_google(google_user_info):
    """Authenticate or create user from Google OAuth"""
    if not google_user_info or not google_user_info.get('email_verified'):
        return None, "Email not verified"
    
    email = google_user_info['email']
    google_id = google_user_info['google_id']
    
    # Check if user exists by Google ID
    user = User.query.filter_by(google_id=google_id).first()
    
    if not user:
        # Check if user exists by email
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Link existing user with Google account
            user.google_id = google_id
            user.oauth_provider = 'google'
        else:
            # Create new user
            user = User(
                email=email,
                full_name=google_user_info.get('name'),
                google_id=google_id,
                oauth_provider='google',
                profile_picture=google_user_info.get('picture'),
                is_verified=True,
                email_verified_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.flush()
            
            # Assign role based on email
            if email == current_app.config['ADMIN_EMAIL']:
                admin_role = Role.query.filter_by(name='admin').first()
                if admin_role:
                    user.add_role(admin_role)
                    current_app.logger.info(f"Admin role assigned to {email}")
            else:
                # Assign default role (editor)
                editor_role = Role.query.filter_by(name='editor').first()
                if editor_role:
                    user.add_role(editor_role)
    
    # Update user information from Google
    user.full_name = google_user_info.get('name', user.full_name)
    user.profile_picture = google_user_info.get('picture', user.profile_picture)
    
    # Log the authentication
    log_activity(
        user_id=user.id,
        action='google_login',
        resource_type='user',
        resource_id=user.id,
        data={'provider': 'google', 'email': email}
    )
    
    db.session.commit()
    return user, None


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            
            # Get user from JWT
            identity = get_jwt_identity()
            if identity:
                user_data = json.loads(identity)
                request.current_user_id = user_data.get('user_id')
                request.current_user_roles = user_data.get('roles', [])
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': 'Authentication required'}), 401
    
    return decorated_function


def require_permission(permission):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()
                
                # Get user from JWT
                identity = get_jwt_identity()
                if not identity:
                    return jsonify({'error': 'Authentication required'}), 401
                
                user_data = json.loads(identity)
                user = User.query.get(user_data.get('user_id'))
                
                if not user or not user.has_permission(permission):
                    log_activity(
                        user_id=user.id if user else None,
                        action='permission_denied',
                        data={'permission': permission}
                    )
                    return jsonify({'error': f'Permission required: {permission}'}), 403
                
                request.current_user = user
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': 'Authentication required'}), 401
        
        return decorated_function
    return decorator


def require_role(role_name):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()
                
                # Get user from JWT
                identity = get_jwt_identity()
                if not identity:
                    return jsonify({'error': 'Authentication required'}), 401
                
                user_data = json.loads(identity)
                
                if role_name not in user_data.get('roles', []):
                    log_activity(
                        user_id=user_data.get('user_id'),
                        action='role_denied',
                        data={'required_role': role_name}
                    )
                    return jsonify({'error': f'Role required: {role_name}'}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': 'Authentication required'}), 401
        
        return decorated_function
    return decorator


def validate_password(password):
    """Validate password strength"""
    errors = []
    
    if len(password) < current_app.config['PASSWORD_MIN_LENGTH']:
        errors.append(f"Password must be at least {current_app.config['PASSWORD_MIN_LENGTH']} characters")
    
    if current_app.config['PASSWORD_REQUIRE_UPPERCASE'] and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if current_app.config['PASSWORD_REQUIRE_LOWERCASE'] and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if current_app.config['PASSWORD_REQUIRE_NUMBERS'] and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    if current_app.config['PASSWORD_REQUIRE_SPECIAL'] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")
    
    return errors


def log_activity(user_id=None, action=None, resource_type=None, 
                resource_id=None, data=None, status_code=200, error_message=None):
    """Log user activity"""
    try:
        activity = ActivityLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            method=request.method if request else None,
            endpoint=request.endpoint if request else None,
            data=data,
            status_code=status_code,
            error_message=error_message
        )
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log activity: {str(e)}")


def generate_verification_token():
    """Generate a secure verification token"""
    return secrets.token_urlsafe(32)


def revoke_user_sessions(user_id):
    """Revoke all active sessions for a user"""
    sessions = UserSession.query.filter_by(
        user_id=user_id,
        is_active=True
    ).all()
    
    for session in sessions:
        session.revoke()
    
    db.session.commit()
    return len(sessions)