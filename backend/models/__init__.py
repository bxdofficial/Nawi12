"""
Database Models for Nawi Admin Dashboard
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()

# Association table for many-to-many relationship between users and roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

# Association table for role permissions
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)


class User(db.Model):
    """User model with support for email/password and Google OAuth"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    full_name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)  # Nullable for OAuth users
    
    # OAuth fields
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    oauth_provider = db.Column(db.String(50), nullable=True)  # 'google', 'github', etc.
    profile_picture = db.Column(db.String(255), nullable=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    
    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, lazy='dynamic',
                           backref=db.backref('users', lazy='dynamic'))
    media_files = db.relationship('MediaFile', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    activity_logs = db.relationship('ActivityLog', backref='user', lazy='dynamic')
    sessions = db.relationship('UserSession', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        """Check if user has specific role"""
        return self.roles.filter_by(name=role_name).first() is not None
    
    def has_permission(self, permission_name):
        """Check if user has specific permission through their roles"""
        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False
    
    def add_role(self, role):
        """Add role to user"""
        if not self.has_role(role.name):
            self.roles.append(role)
    
    def remove_role(self, role):
        """Remove role from user"""
        if self.has_role(role.name):
            self.roles.remove(role)
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'full_name': self.full_name,
            'profile_picture': self.profile_picture,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'roles': [role.name for role in self.roles],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None
        }


class Role(db.Model):
    """Role model for RBAC"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    is_system = db.Column(db.Boolean, default=False)  # System roles cannot be deleted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    permissions = db.relationship('Permission', secondary=role_permissions, lazy='dynamic',
                                 backref=db.backref('roles', lazy='dynamic'))
    
    def has_permission(self, permission_name):
        """Check if role has specific permission"""
        return self.permissions.filter_by(name=permission_name).first() is not None
    
    def add_permission(self, permission):
        """Add permission to role"""
        if not self.has_permission(permission.name):
            self.permissions.append(permission)
    
    def remove_permission(self, permission):
        """Remove permission from role"""
        if self.has_permission(permission.name):
            self.permissions.remove(permission)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_system': self.is_system,
            'permissions': [p.name for p in self.permissions],
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Permission(db.Model):
    """Permission model for fine-grained access control"""
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    category = db.Column(db.String(80), nullable=False)  # 'users', 'media', 'settings', etc.
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'description': self.description
        }


class MediaFile(db.Model):
    """Media file model for managing uploads"""
    __tablename__ = 'media_files'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_url = db.Column(db.String(500), nullable=True)
    
    # File metadata
    file_type = db.Column(db.String(50), nullable=False)  # image, video, document
    mime_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    
    # Image specific metadata
    width = db.Column(db.Integer, nullable=True)
    height = db.Column(db.Integer, nullable=True)
    thumbnail_path = db.Column(db.String(500), nullable=True)
    
    # SEO and organization
    title = db.Column(db.String(255), nullable=True)
    alt_text = db.Column(db.String(500), nullable=True)
    description = db.Column(db.Text, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    
    # Storage information
    storage_provider = db.Column(db.String(50), default='local')  # local, s3, etc.
    s3_key = db.Column(db.String(500), nullable=True)
    
    # Soft delete
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    
    # Ownership and timestamps
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def soft_delete(self):
        """Mark file as deleted without removing from database"""
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
    
    def restore(self):
        """Restore soft-deleted file"""
        self.is_deleted = False
        self.deleted_at = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_url': self.file_url,
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'file_size': self.file_size,
            'width': self.width,
            'height': self.height,
            'thumbnail_url': self.thumbnail_path,
            'title': self.title,
            'alt_text': self.alt_text,
            'description': self.description,
            'tags': self.tags,
            'owner_id': self.owner_id,
            'is_deleted': self.is_deleted,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ActivityLog(db.Model):
    """Activity/Audit log for tracking all system actions"""
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # login, upload, delete, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # user, media, page, etc.
    resource_id = db.Column(db.Integer, nullable=True)
    
    # Request information
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    method = db.Column(db.String(10), nullable=True)  # GET, POST, etc.
    endpoint = db.Column(db.String(255), nullable=True)
    
    # Additional data
    data = db.Column(db.JSON, nullable=True)  # Store additional context
    status_code = db.Column(db.Integer, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user': self.user.email if self.user else None,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'ip_address': self.ip_address,
            'method': self.method,
            'endpoint': self.endpoint,
            'status_code': self.status_code,
            'error_message': self.error_message,
            'data': self.data,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class SiteSettings(db.Model):
    """Site-wide settings"""
    __tablename__ = 'site_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    value_type = db.Column(db.String(20), default='string')  # string, json, boolean, number
    category = db.Column(db.String(50), nullable=False)  # general, email, storage, security
    description = db.Column(db.String(255), nullable=True)
    is_public = db.Column(db.Boolean, default=False)  # Can be exposed to frontend
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    @property
    def parsed_value(self):
        """Get parsed value based on type"""
        if self.value_type == 'json':
            return json.loads(self.value) if self.value else None
        elif self.value_type == 'boolean':
            return self.value.lower() == 'true' if self.value else False
        elif self.value_type == 'number':
            return float(self.value) if self.value else 0
        return self.value
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.parsed_value,
            'category': self.category,
            'description': self.description,
            'is_public': self.is_public,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class UserSession(db.Model):
    """Track user sessions for security"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(500), unique=True, nullable=False)
    refresh_token = db.Column(db.String(500), unique=True, nullable=True)
    
    # Session information
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    device_type = db.Column(db.String(50), nullable=True)  # desktop, mobile, tablet
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_valid(self):
        """Check if session is valid"""
        return (self.is_active and 
                self.expires_at > datetime.utcnow() and 
                self.revoked_at is None)
    
    def revoke(self):
        """Revoke session"""
        self.is_active = False
        self.revoked_at = datetime.utcnow()


class Backup(db.Model):
    """Database backup records"""
    __tablename__ = 'backups'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    backup_type = db.Column(db.String(50), nullable=False)  # full, incremental, media
    
    # Status
    status = db.Column(db.String(50), default='pending')  # pending, completed, failed
    error_message = db.Column(db.Text, nullable=True)
    
    # Metadata
    includes_media = db.Column(db.Boolean, default=False)
    database_size = db.Column(db.BigInteger, nullable=True)
    media_size = db.Column(db.BigInteger, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_size': self.file_size,
            'backup_type': self.backup_type,
            'status': self.status,
            'includes_media': self.includes_media,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class Page(db.Model):
    """Dynamic pages/content management"""
    __tablename__ = 'pages'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=True)
    content_type = db.Column(db.String(50), default='html')  # html, markdown, json
    
    # SEO
    meta_title = db.Column(db.String(255), nullable=True)
    meta_description = db.Column(db.Text, nullable=True)
    meta_keywords = db.Column(db.String(500), nullable=True)
    
    # Status
    is_published = db.Column(db.Boolean, default=False)
    published_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'slug': self.slug,
            'content': self.content,
            'content_type': self.content_type,
            'is_published': self.is_published,
            'published_at': self.published_at.isoformat() if self.published_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


def init_default_roles_and_permissions():
    """Initialize default roles and permissions"""
    # Default permissions
    default_permissions = [
        # User management
        ('users.view', 'users', 'View users'),
        ('users.create', 'users', 'Create users'),
        ('users.edit', 'users', 'Edit users'),
        ('users.delete', 'users', 'Delete users'),
        ('users.manage_roles', 'users', 'Manage user roles'),
        
        # Media management
        ('media.view', 'media', 'View media files'),
        ('media.upload', 'media', 'Upload media files'),
        ('media.edit', 'media', 'Edit media metadata'),
        ('media.delete', 'media', 'Delete media files'),
        
        # Page management
        ('pages.view', 'pages', 'View pages'),
        ('pages.create', 'pages', 'Create pages'),
        ('pages.edit', 'pages', 'Edit pages'),
        ('pages.delete', 'pages', 'Delete pages'),
        ('pages.publish', 'pages', 'Publish/unpublish pages'),
        
        # Settings management
        ('settings.view', 'settings', 'View settings'),
        ('settings.edit', 'settings', 'Edit settings'),
        
        # Role management
        ('roles.view', 'roles', 'View roles'),
        ('roles.create', 'roles', 'Create roles'),
        ('roles.edit', 'roles', 'Edit roles'),
        ('roles.delete', 'roles', 'Delete roles'),
        
        # Activity logs
        ('logs.view', 'logs', 'View activity logs'),
        ('logs.export', 'logs', 'Export activity logs'),
        
        # Backups
        ('backups.view', 'backups', 'View backups'),
        ('backups.create', 'backups', 'Create backups'),
        ('backups.restore', 'backups', 'Restore backups'),
        ('backups.delete', 'backups', 'Delete backups'),
    ]
    
    # Create permissions
    for name, category, description in default_permissions:
        permission = Permission.query.filter_by(name=name).first()
        if not permission:
            permission = Permission(name=name, category=category, description=description)
            db.session.add(permission)
    
    # Default roles
    default_roles = [
        ('admin', 'Full system access', True, [
            'users.view', 'users.create', 'users.edit', 'users.delete', 'users.manage_roles',
            'media.view', 'media.upload', 'media.edit', 'media.delete',
            'pages.view', 'pages.create', 'pages.edit', 'pages.delete', 'pages.publish',
            'settings.view', 'settings.edit',
            'roles.view', 'roles.create', 'roles.edit', 'roles.delete',
            'logs.view', 'logs.export',
            'backups.view', 'backups.create', 'backups.restore', 'backups.delete'
        ]),
        ('editor', 'Content management access', True, [
            'media.view', 'media.upload', 'media.edit',
            'pages.view', 'pages.create', 'pages.edit', 'pages.publish',
            'logs.view'
        ]),
        ('viewer', 'Read-only access', True, [
            'users.view',
            'media.view',
            'pages.view',
            'settings.view',
            'logs.view',
            'backups.view'
        ])
    ]
    
    # Create roles with permissions
    for role_name, description, is_system, permission_names in default_roles:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name, description=description, is_system=is_system)
            db.session.add(role)
            db.session.flush()
            
            # Add permissions to role
            for perm_name in permission_names:
                permission = Permission.query.filter_by(name=perm_name).first()
                if permission:
                    role.add_permission(permission)
    
    db.session.commit()