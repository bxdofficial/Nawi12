"""
Authentication routes including Google OAuth
"""

from flask import Blueprint, request, jsonify, redirect, url_for, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime

from models import db, User, Role
from utils.auth import (
    create_tokens, verify_google_token, get_google_oauth_url,
    exchange_google_code, authenticate_with_google,
    validate_password, log_activity, revoke_user_sessions
)

auth_bp = Blueprint('auth', __name__)
limiter = Limiter(key_func=get_remote_address)


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10/hour")
def login():
    """Traditional email/password login"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user:
            log_activity(action='login_failed', data={'email': email, 'reason': 'user_not_found'})
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is active
        if not user.is_active:
            log_activity(user_id=user.id, action='login_failed', data={'reason': 'account_inactive'})
            return jsonify({'error': 'Account is disabled'}), 403
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            log_activity(user_id=user.id, action='login_failed', data={'reason': 'account_locked'})
            return jsonify({'error': 'Account is temporarily locked'}), 403
        
        # Verify password
        if not user.check_password(password):
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(hours=1)
                log_activity(user_id=user.id, action='account_locked', data={'failed_attempts': user.failed_login_attempts})
            
            db.session.commit()
            log_activity(user_id=user.id, action='login_failed', data={'reason': 'invalid_password'})
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check email verification
        if current_app.config.get('EMAIL_VERIFICATION_REQUIRED') and not user.is_verified:
            return jsonify({'error': 'Email not verified'}), 403
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # Create tokens
        tokens = create_tokens(user)
        
        # Log successful login
        log_activity(user_id=user.id, action='login', resource_type='user', resource_id=user.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'tokens': tokens
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5/hour")
def register():
    """User registration"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        
        # Check if registration is enabled
        if not current_app.config.get('REGISTRATION_ENABLED', True):
            return jsonify({'error': 'Registration is currently disabled'}), 403
        
        # Validate email
        if not email or '@' not in email:
            return jsonify({'error': 'Valid email required'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Validate password
        password_errors = validate_password(password)
        if password_errors:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        # Create user
        user = User(
            email=email,
            full_name=full_name,
            is_active=True,
            is_verified=False
        )
        user.set_password(password)
        
        # Assign default role
        default_role = Role.query.filter_by(name='viewer').first()
        if default_role:
            user.add_role(default_role)
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email (TODO: implement email sending)
        # send_verification_email(user)
        
        # Log registration
        log_activity(user_id=user.id, action='register', resource_type='user', resource_id=user.id)
        
        return jsonify({
            'message': 'Registration successful. Please verify your email.',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/google', methods=['GET'])
def google_login():
    """Initiate Google OAuth flow"""
    auth_url = get_google_oauth_url()
    return jsonify({'auth_url': auth_url}), 200


@auth_bp.route('/google/callback', methods=['GET', 'POST'])
def google_callback():
    """Handle Google OAuth callback"""
    try:
        # Get authorization code
        code = request.args.get('code') or request.json.get('code')
        
        if not code:
            return jsonify({'error': 'Authorization code missing'}), 400
        
        # Exchange code for tokens
        token_data = exchange_google_code(code)
        
        if not token_data:
            return jsonify({'error': 'Failed to exchange authorization code'}), 400
        
        # Verify ID token
        google_user_info = verify_google_token(token_data.get('id_token'))
        
        if not google_user_info:
            return jsonify({'error': 'Invalid Google token'}), 401
        
        # Authenticate or create user
        user, error = authenticate_with_google(google_user_info)
        
        if error:
            return jsonify({'error': error}), 400
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 403
        
        # Create tokens
        tokens = create_tokens(user)
        
        # Log successful Google login
        log_activity(user_id=user.id, action='google_login', resource_type='user', resource_id=user.id)
        
        # Redirect to frontend with tokens (or return JSON for API)
        if request.args.get('redirect'):
            frontend_url = current_app.config['FRONTEND_URL']
            return redirect(f"{frontend_url}/auth/success?token={tokens['access_token']}")
        
        return jsonify({
            'message': 'Google login successful',
            'user': user.to_dict(),
            'tokens': tokens
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Google OAuth error: {str(e)}")
        return jsonify({'error': 'Google authentication failed'}), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh access token"""
    try:
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        user = User.query.get(user_data.get('user_id'))
        
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid user'}), 401
        
        # Create new tokens
        tokens = create_tokens(user)
        
        return jsonify({
            'message': 'Token refreshed',
            'tokens': tokens
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user and revoke tokens"""
    try:
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        user_id = user_data.get('user_id')
        
        # Revoke all user sessions
        revoked_count = revoke_user_sessions(user_id)
        
        # Log logout
        log_activity(user_id=user_id, action='logout')
        
        return jsonify({
            'message': 'Logout successful',
            'sessions_revoked': revoked_count
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    """Verify user email"""
    # TODO: Implement email verification
    pass


@auth_bp.route('/forgot-password', methods=['POST'])
@limiter.limit("3/hour")
def forgot_password():
    """Initiate password reset"""
    # TODO: Implement password reset
    pass


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    # TODO: Implement password reset
    pass


# Import required modules
import json
from datetime import timedelta