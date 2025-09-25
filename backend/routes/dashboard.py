"""
Dashboard overview routes
"""

from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta
from sqlalchemy import func

from models import db, User, MediaFile, Page, ActivityLog
from utils.auth import require_permission

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
@require_permission('users.view')
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # User statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        verified_users = User.query.filter_by(is_verified=True).count()
        new_users_week = User.query.filter(
            User.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        # Media statistics
        total_media = MediaFile.query.filter_by(is_deleted=False).count()
        total_media_size = db.session.query(
            func.sum(MediaFile.file_size)
        ).filter_by(is_deleted=False).scalar() or 0
        
        media_by_type = db.session.query(
            MediaFile.file_type,
            func.count(MediaFile.id)
        ).filter_by(is_deleted=False).group_by(MediaFile.file_type).all()
        
        # Page statistics
        total_pages = Page.query.count()
        published_pages = Page.query.filter_by(is_published=True).count()
        
        # Activity statistics
        total_activities_today = ActivityLog.query.filter(
            ActivityLog.created_at >= datetime.utcnow().date()
        ).count()
        
        recent_activities = ActivityLog.query.order_by(
            ActivityLog.created_at.desc()
        ).limit(10).all()
        
        # Storage usage
        max_storage = current_app.config.get('MAX_STORAGE_SIZE', 10737418240)  # 10GB default
        storage_percentage = (total_media_size / max_storage * 100) if max_storage else 0
        
        return jsonify({
            'users': {
                'total': total_users,
                'active': active_users,
                'verified': verified_users,
                'new_this_week': new_users_week
            },
            'media': {
                'total_files': total_media,
                'total_size': total_media_size,
                'by_type': dict(media_by_type)
            },
            'pages': {
                'total': total_pages,
                'published': published_pages
            },
            'storage': {
                'used': total_media_size,
                'total': max_storage,
                'percentage': round(storage_percentage, 2)
            },
            'activity': {
                'today': total_activities_today,
                'recent': [activity.to_dict() for activity in recent_activities]
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Dashboard stats error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve dashboard statistics'}), 500


@dashboard_bp.route('/charts/user-growth', methods=['GET'])
@jwt_required()
@require_permission('users.view')
def get_user_growth_chart():
    """Get user growth data for charts"""
    try:
        # Get data for last 30 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        # Query daily user registrations
        daily_registrations = db.session.query(
            func.date(User.created_at).label('date'),
            func.count(User.id).label('count')
        ).filter(
            User.created_at >= start_date
        ).group_by(
            func.date(User.created_at)
        ).all()
        
        # Format data for chart
        chart_data = []
        for registration in daily_registrations:
            chart_data.append({
                'date': registration.date.isoformat() if registration.date else None,
                'users': registration.count
            })
        
        return jsonify({'data': chart_data}), 200
        
    except Exception as e:
        current_app.logger.error(f"User growth chart error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve chart data'}), 500


@dashboard_bp.route('/charts/media-uploads', methods=['GET'])
@jwt_required()
@require_permission('media.view')
def get_media_uploads_chart():
    """Get media uploads data for charts"""
    try:
        # Get data for last 30 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        # Query daily media uploads
        daily_uploads = db.session.query(
            func.date(MediaFile.created_at).label('date'),
            func.count(MediaFile.id).label('count'),
            func.sum(MediaFile.file_size).label('size')
        ).filter(
            MediaFile.created_at >= start_date,
            MediaFile.is_deleted == False
        ).group_by(
            func.date(MediaFile.created_at)
        ).all()
        
        # Format data for chart
        chart_data = []
        for upload in daily_uploads:
            chart_data.append({
                'date': upload.date.isoformat() if upload.date else None,
                'files': upload.count,
                'size': upload.size or 0
            })
        
        return jsonify({'data': chart_data}), 200
        
    except Exception as e:
        current_app.logger.error(f"Media uploads chart error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve chart data'}), 500