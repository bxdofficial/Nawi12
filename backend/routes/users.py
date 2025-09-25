"""
User management routes
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from sqlalchemy import or_
from datetime import datetime

from models import db, User, Role
from utils.auth import require_permission, log_activity, validate_password

users_bp = Blueprint('users', __name__)


@users_bp.route('', methods=['GET'])
@jwt_required()
@require_permission('users.view')
def get_users():
    """Get all users with pagination and filtering"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '')
        role = request.args.get('role', '')
        status = request.args.get('status', '')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Build query
        query = User.query
        
        # Apply search filter
        if search:
            query = query.filter(
                or_(
                    User.email.ilike(f'%{search}%'),
                    User.full_name.ilike(f'%{search}%'),
                    User.username.ilike(f'%{search}%')
                )
            )
        
        # Apply role filter
        if role:
            query = query.join(User.roles).filter(Role.name == role)
        
        # Apply status filter
        if status == 'active':
            query = query.filter(User.is_active == True)
        elif status == 'inactive':
            query = query.filter(User.is_active == False)
        elif status == 'verified':
            query = query.filter(User.is_verified == True)
        elif status == 'unverified':
            query = query.filter(User.is_verified == False)
        
        # Apply sorting
        if sort_order == 'desc':
            query = query.order_by(getattr(User, sort_by).desc())
        else:
            query = query.order_by(getattr(User, sort_by))
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Prepare response
        users = [user.to_dict() for user in pagination.items]
        
        return jsonify({
            'users': users,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get users error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve users'}), 500


@users_bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
@require_permission('users.view')
def get_user(user_id):
    """Get a specific user"""
    try:
        user = User.query.get_or_404(user_id)
        return jsonify({'user': user.to_dict()}), 200
    except Exception as e:
        current_app.logger.error(f"Get user error: {str(e)}")
        return jsonify({'error': 'User not found'}), 404


@users_bp.route('', methods=['POST'])
@jwt_required()
@require_permission('users.create')
def create_user():
    """Create a new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        email = data.get('email', '').lower().strip()
        if not email or '@' not in email:
            return jsonify({'error': 'Valid email required'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create user
        user = User(
            email=email,
            username=data.get('username'),
            full_name=data.get('full_name'),
            is_active=data.get('is_active', True),
            is_verified=data.get('is_verified', False)
        )
        
        # Set password if provided
        if data.get('password'):
            password_errors = validate_password(data['password'])
            if password_errors:
                return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
            user.set_password(data['password'])
        
        # Assign roles
        role_names = data.get('roles', ['viewer'])
        for role_name in role_names:
            role = Role.query.filter_by(name=role_name).first()
            if role:
                user.add_role(role)
        
        db.session.add(user)
        db.session.commit()
        
        # Log activity
        log_activity(
            action='user_created',
            resource_type='user',
            resource_id=user.id,
            data={'email': email}
        )
        
        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Create user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create user'}), 500


@users_bp.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
@require_permission('users.edit')
def update_user(user_id):
    """Update a user"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        # Update user fields
        if 'email' in data:
            email = data['email'].lower().strip()
            if email != user.email:
                if User.query.filter_by(email=email).first():
                    return jsonify({'error': 'Email already in use'}), 409
                user.email = email
        
        if 'username' in data:
            username = data['username']
            if username != user.username:
                if User.query.filter_by(username=username).first():
                    return jsonify({'error': 'Username already in use'}), 409
                user.username = username
        
        if 'full_name' in data:
            user.full_name = data['full_name']
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        if 'is_verified' in data:
            user.is_verified = data['is_verified']
            if data['is_verified']:
                user.email_verified_at = datetime.utcnow()
        
        # Update password if provided
        if 'password' in data and data['password']:
            password_errors = validate_password(data['password'])
            if password_errors:
                return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
            user.set_password(data['password'])
        
        # Update roles
        if 'roles' in data:
            # Remove all current roles
            for role in user.roles.all():
                user.remove_role(role)
            
            # Add new roles
            for role_name in data['roles']:
                role = Role.query.filter_by(name=role_name).first()
                if role:
                    user.add_role(role)
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log activity
        log_activity(
            action='user_updated',
            resource_type='user',
            resource_id=user.id,
            data={'changes': list(data.keys())}
        )
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Update user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update user'}), 500


@users_bp.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
@require_permission('users.delete')
def delete_user(user_id):
    """Delete a user"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent deleting system admin
        if user.email == current_app.config['ADMIN_EMAIL']:
            return jsonify({'error': 'Cannot delete system administrator'}), 403
        
        # Store user info for logging
        user_email = user.email
        
        db.session.delete(user)
        db.session.commit()
        
        # Log activity
        log_activity(
            action='user_deleted',
            resource_type='user',
            resource_id=user_id,
            data={'email': user_email}
        )
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Delete user error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete user'}), 500


@users_bp.route('/<int:user_id>/toggle-status', methods=['POST'])
@jwt_required()
@require_permission('users.edit')
def toggle_user_status(user_id):
    """Toggle user active status"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Prevent disabling system admin
        if user.email == current_app.config['ADMIN_EMAIL'] and user.is_active:
            return jsonify({'error': 'Cannot disable system administrator'}), 403
        
        user.is_active = not user.is_active
        db.session.commit()
        
        # Log activity
        log_activity(
            action='user_status_toggled',
            resource_type='user',
            resource_id=user_id,
            data={'new_status': 'active' if user.is_active else 'inactive'}
        )
        
        return jsonify({
            'message': f'User {"activated" if user.is_active else "deactivated"} successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Toggle user status error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to toggle user status'}), 500


@users_bp.route('/<int:user_id>/reset-password', methods=['POST'])
@jwt_required()
@require_permission('users.edit')
def reset_user_password(user_id):
    """Reset user password"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        new_password = data.get('password')
        if not new_password:
            return jsonify({'error': 'New password required'}), 400
        
        # Validate password
        password_errors = validate_password(new_password)
        if password_errors:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        user.set_password(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        # TODO: Send password reset email notification
        
        # Log activity
        log_activity(
            action='password_reset_admin',
            resource_type='user',
            resource_id=user_id
        )
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Reset password error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to reset password'}), 500


@users_bp.route('/roles', methods=['GET'])
@jwt_required()
@require_permission('users.view')
def get_roles():
    """Get all available roles"""
    try:
        roles = Role.query.all()
        return jsonify({
            'roles': [role.to_dict() for role in roles]
        }), 200
    except Exception as e:
        current_app.logger.error(f"Get roles error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve roles'}), 500