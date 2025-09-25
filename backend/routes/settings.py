"""
Settings management routes
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
import json

from models import db, SiteSettings
from utils.auth import require_permission, log_activity

settings_bp = Blueprint('settings', __name__)


@settings_bp.route('', methods=['GET'])
@jwt_required()
@require_permission('settings.view')
def get_settings():
    """Get all settings"""
    try:
        settings = SiteSettings.query.all()
        return jsonify({'settings': [setting.to_dict() for setting in settings]}), 200
    except Exception as e:
        current_app.logger.error(f"Get settings error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve settings'}), 500


@settings_bp.route('/<string:key>', methods=['PUT'])
@jwt_required()
@require_permission('settings.edit')
def update_setting(key):
    """Update a setting"""
    try:
        data = request.get_json()
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        
        setting = SiteSettings.query.filter_by(key=key).first()
        if not setting:
            return jsonify({'error': 'Setting not found'}), 404
        
        setting.value = str(data.get('value'))
        setting.updated_by = user_data.get('user_id')
        db.session.commit()
        
        log_activity(
            user_id=user_data.get('user_id'),
            action='setting_updated',
            resource_type='setting',
            data={'key': key, 'new_value': setting.value}
        )
        
        return jsonify({'setting': setting.to_dict()}), 200
    except Exception as e:
        current_app.logger.error(f"Update setting error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update setting'}), 500