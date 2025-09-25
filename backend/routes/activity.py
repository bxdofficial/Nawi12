"""
Activity log routes
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta

from models import db, ActivityLog
from utils.auth import require_permission

activity_bp = Blueprint('activity', __name__)


@activity_bp.route('', methods=['GET'])
@jwt_required()
@require_permission('logs.view')
def get_activity_logs():
    """Get activity logs with filtering"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        user_id = request.args.get('user_id', type=int)
        action = request.args.get('action')
        resource_type = request.args.get('resource_type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = ActivityLog.query
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        if action:
            query = query.filter_by(action=action)
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        if start_date:
            start = datetime.fromisoformat(start_date)
            query = query.filter(ActivityLog.created_at >= start)
        if end_date:
            end = datetime.fromisoformat(end_date)
            query = query.filter(ActivityLog.created_at <= end)
        
        # Order by most recent
        query = query.order_by(ActivityLog.created_at.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'logs': [log.to_dict() for log in pagination.items],
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get activity logs error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve activity logs'}), 500