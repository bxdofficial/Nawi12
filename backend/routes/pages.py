"""
Page management routes
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import json

from models import db, Page
from utils.auth import require_permission, log_activity

pages_bp = Blueprint('pages', __name__)


@pages_bp.route('', methods=['GET'])
@jwt_required()
@require_permission('pages.view')
def get_pages():
    """Get all pages"""
    try:
        pages = Page.query.all()
        return jsonify({'pages': [page.to_dict() for page in pages]}), 200
    except Exception as e:
        current_app.logger.error(f"Get pages error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve pages'}), 500


@pages_bp.route('', methods=['POST'])
@jwt_required()
@require_permission('pages.create')
def create_page():
    """Create new page"""
    try:
        data = request.get_json()
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        
        page = Page(
            title=data.get('title'),
            slug=data.get('slug'),
            content=data.get('content'),
            content_type=data.get('content_type', 'html'),
            meta_title=data.get('meta_title'),
            meta_description=data.get('meta_description'),
            meta_keywords=data.get('meta_keywords'),
            is_published=data.get('is_published', False),
            created_by=user_data.get('user_id')
        )
        
        if page.is_published:
            page.published_at = datetime.utcnow()
        
        db.session.add(page)
        db.session.commit()
        
        log_activity(
            user_id=user_data.get('user_id'),
            action='page_created',
            resource_type='page',
            resource_id=page.id,
            data={'title': page.title}
        )
        
        return jsonify({'page': page.to_dict()}), 201
    except Exception as e:
        current_app.logger.error(f"Create page error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create page'}), 500