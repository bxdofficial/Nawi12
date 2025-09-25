"""
Backup and restore routes
"""

import os
import shutil
import tarfile
from datetime import datetime
from flask import Blueprint, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
import json

from models import db, Backup
from utils.auth import require_permission, log_activity

backup_bp = Blueprint('backup', __name__)


@backup_bp.route('', methods=['GET'])
@jwt_required()
@require_permission('backups.view')
def get_backups():
    """Get all backups"""
    try:
        backups = Backup.query.order_by(Backup.created_at.desc()).all()
        return jsonify({'backups': [backup.to_dict() for backup in backups]}), 200
    except Exception as e:
        current_app.logger.error(f"Get backups error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve backups'}), 500


@backup_bp.route('/create', methods=['POST'])
@jwt_required()
@require_permission('backups.create')
def create_backup():
    """Create a new backup"""
    try:
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        
        # Create backup directory
        backup_dir = os.path.join(current_app.root_path, current_app.config['BACKUP_FOLDER'])
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate backup filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.tar.gz"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Create backup record
        backup = Backup(
            filename=backup_filename,
            file_path=backup_path,
            backup_type='full',
            status='pending',
            created_by=user_data.get('user_id')
        )
        db.session.add(backup)
        db.session.flush()
        
        try:
            # Create tar archive
            with tarfile.open(backup_path, "w:gz") as tar:
                # Backup database
                db_path = current_app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
                if os.path.exists(db_path):
                    tar.add(db_path, arcname='database.db')
                    backup.database_size = os.path.getsize(db_path)
                
                # Backup uploads folder
                uploads_dir = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
                if os.path.exists(uploads_dir):
                    tar.add(uploads_dir, arcname='uploads')
                    backup.includes_media = True
            
            # Update backup status
            backup.file_size = os.path.getsize(backup_path)
            backup.status = 'completed'
            backup.completed_at = datetime.utcnow()
            
        except Exception as e:
            backup.status = 'failed'
            backup.error_message = str(e)
            raise e
        
        db.session.commit()
        
        log_activity(
            user_id=user_data.get('user_id'),
            action='backup_created',
            resource_type='backup',
            resource_id=backup.id,
            data={'filename': backup_filename}
        )
        
        return jsonify({
            'message': 'Backup created successfully',
            'backup': backup.to_dict()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Create backup error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create backup'}), 500


@backup_bp.route('/<int:backup_id>/download', methods=['GET'])
@jwt_required()
@require_permission('backups.view')
def download_backup(backup_id):
    """Download a backup file"""
    try:
        backup = Backup.query.get_or_404(backup_id)
        
        if not os.path.exists(backup.file_path):
            return jsonify({'error': 'Backup file not found'}), 404
        
        return send_file(
            backup.file_path,
            as_attachment=True,
            download_name=backup.filename
        )
    except Exception as e:
        current_app.logger.error(f"Download backup error: {str(e)}")
        return jsonify({'error': 'Failed to download backup'}), 500