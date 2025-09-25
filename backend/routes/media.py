"""
Media management routes with drag-and-drop support
"""

import os
import json
import shutil
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from PIL import Image
import magic

from models import db, MediaFile, User
from utils.auth import require_permission, log_activity

media_bp = Blueprint('media', __name__)


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def get_file_type(mime_type):
    """Determine file type from MIME type"""
    if mime_type.startswith('image/'):
        return 'image'
    elif mime_type.startswith('video/'):
        return 'video'
    elif mime_type.startswith('application/pdf'):
        return 'document'
    elif mime_type.startswith('application/') or mime_type.startswith('text/'):
        return 'document'
    else:
        return 'other'


def create_thumbnail(image_path, thumbnail_path, size=(200, 200)):
    """Create thumbnail for image"""
    try:
        with Image.open(image_path) as img:
            img.thumbnail(size, Image.Resampling.LANCZOS)
            img.save(thumbnail_path, optimize=True, quality=85)
        return True
    except Exception as e:
        current_app.logger.error(f"Thumbnail creation failed: {str(e)}")
        return False


@media_bp.route('', methods=['GET'])
@jwt_required()
@require_permission('media.view')
def get_media_files():
    """Get all media files with pagination and filtering"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        file_type = request.args.get('type', '')
        search = request.args.get('search', '')
        tags = request.args.get('tags', '')
        show_deleted = request.args.get('show_deleted', 'false').lower() == 'true'
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Build query
        query = MediaFile.query
        
        # Filter by deletion status
        if not show_deleted:
            query = query.filter(MediaFile.is_deleted == False)
        
        # Filter by file type
        if file_type:
            query = query.filter(MediaFile.file_type == file_type)
        
        # Search filter
        if search:
            query = query.filter(
                db.or_(
                    MediaFile.filename.ilike(f'%{search}%'),
                    MediaFile.original_filename.ilike(f'%{search}%'),
                    MediaFile.title.ilike(f'%{search}%'),
                    MediaFile.description.ilike(f'%{search}%')
                )
            )
        
        # Tags filter (JSON field)
        if tags:
            tag_list = tags.split(',')
            for tag in tag_list:
                query = query.filter(MediaFile.tags.contains([tag.strip()]))
        
        # Apply sorting
        if hasattr(MediaFile, sort_by):
            if sort_order == 'desc':
                query = query.order_by(getattr(MediaFile, sort_by).desc())
            else:
                query = query.order_by(getattr(MediaFile, sort_by))
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Prepare response
        files = [file.to_dict() for file in pagination.items]
        
        return jsonify({
            'files': files,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Get media files error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve media files'}), 500


@media_bp.route('/upload', methods=['POST'])
@jwt_required()
@require_permission('media.upload')
def upload_file():
    """Upload single or multiple files with drag-and-drop support"""
    try:
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        user_id = user_data.get('user_id')
        
        if 'files' not in request.files and 'file' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        # Handle both single and multiple files
        files = request.files.getlist('files') or [request.files.get('file')]
        uploaded_files = []
        errors = []
        
        for file in files:
            if file and file.filename:
                # Check file extension
                if not allowed_file(file.filename):
                    errors.append(f"{file.filename}: File type not allowed")
                    continue
                
                # Secure filename
                original_filename = file.filename
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{timestamp}{ext}"
                
                # Determine file type from MIME
                mime = magic.Magic(mime=True)
                file_content = file.read()
                mime_type = mime.from_buffer(file_content)
                file_type = get_file_type(mime_type)
                
                # Reset file pointer
                file.seek(0)
                
                # Create directory structure
                upload_folder = os.path.join(
                    current_app.config['UPLOAD_FOLDER'],
                    file_type + 's'  # images, videos, documents
                )
                os.makedirs(upload_folder, exist_ok=True)
                
                # Save file
                file_path = os.path.join(upload_folder, filename)
                full_path = os.path.join(current_app.root_path, file_path)
                file.save(full_path)
                
                # Get file size
                file_size = os.path.getsize(full_path)
                
                # Process image files
                width = height = None
                thumbnail_path = None
                if file_type == 'image':
                    try:
                        with Image.open(full_path) as img:
                            width, height = img.size
                            
                            # Create thumbnail
                            thumb_folder = os.path.join(
                                current_app.config['UPLOAD_FOLDER'],
                                'thumbnails'
                            )
                            os.makedirs(thumb_folder, exist_ok=True)
                            
                            thumb_filename = f"thumb_{filename}"
                            thumb_path = os.path.join(thumb_folder, thumb_filename)
                            thumb_full_path = os.path.join(current_app.root_path, thumb_path)
                            
                            if create_thumbnail(full_path, thumb_full_path):
                                thumbnail_path = f"/uploads/thumbnails/{thumb_filename}"
                    except Exception as e:
                        current_app.logger.error(f"Image processing error: {str(e)}")
                
                # Create database record
                media_file = MediaFile(
                    filename=filename,
                    original_filename=original_filename,
                    file_path=file_path,
                    file_url=f"/uploads/{file_type}s/{filename}",
                    file_type=file_type,
                    mime_type=mime_type,
                    file_size=file_size,
                    width=width,
                    height=height,
                    thumbnail_path=thumbnail_path,
                    owner_id=user_id,
                    title=request.form.get('title', original_filename),
                    alt_text=request.form.get('alt_text', ''),
                    description=request.form.get('description', ''),
                    tags=json.loads(request.form.get('tags', '[]'))
                )
                
                db.session.add(media_file)
                db.session.flush()
                
                uploaded_files.append(media_file.to_dict())
                
                # Log activity
                log_activity(
                    user_id=user_id,
                    action='media_upload',
                    resource_type='media',
                    resource_id=media_file.id,
                    data={'filename': original_filename, 'size': file_size}
                )
        
        db.session.commit()
        
        return jsonify({
            'message': 'Files uploaded successfully',
            'files': uploaded_files,
            'errors': errors
        }), 201 if uploaded_files else 400
        
    except Exception as e:
        current_app.logger.error(f"Upload error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Upload failed'}), 500


@media_bp.route('/<int:file_id>', methods=['GET'])
@jwt_required()
@require_permission('media.view')
def get_media_file(file_id):
    """Get specific media file details"""
    try:
        media_file = MediaFile.query.get_or_404(file_id)
        return jsonify({'file': media_file.to_dict()}), 200
    except Exception as e:
        current_app.logger.error(f"Get media file error: {str(e)}")
        return jsonify({'error': 'File not found'}), 404


@media_bp.route('/<int:file_id>', methods=['PUT'])
@jwt_required()
@require_permission('media.edit')
def update_media_file(file_id):
    """Update media file metadata"""
    try:
        media_file = MediaFile.query.get_or_404(file_id)
        data = request.get_json()
        
        # Update metadata
        if 'title' in data:
            media_file.title = data['title']
        if 'alt_text' in data:
            media_file.alt_text = data['alt_text']
        if 'description' in data:
            media_file.description = data['description']
        if 'tags' in data:
            media_file.tags = data['tags']
        
        media_file.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log activity
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        log_activity(
            user_id=user_data.get('user_id'),
            action='media_updated',
            resource_type='media',
            resource_id=file_id,
            data={'changes': list(data.keys())}
        )
        
        return jsonify({
            'message': 'File updated successfully',
            'file': media_file.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Update media error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update file'}), 500


@media_bp.route('/<int:file_id>', methods=['DELETE'])
@jwt_required()
@require_permission('media.delete')
def delete_media_file(file_id):
    """Soft delete media file"""
    try:
        media_file = MediaFile.query.get_or_404(file_id)
        
        # Soft delete
        media_file.soft_delete()
        db.session.commit()
        
        # Log activity
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        log_activity(
            user_id=user_data.get('user_id'),
            action='media_deleted',
            resource_type='media',
            resource_id=file_id,
            data={'filename': media_file.original_filename}
        )
        
        return jsonify({'message': 'File deleted successfully'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Delete media error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete file'}), 500


@media_bp.route('/<int:file_id>/restore', methods=['POST'])
@jwt_required()
@require_permission('media.edit')
def restore_media_file(file_id):
    """Restore soft-deleted file"""
    try:
        media_file = MediaFile.query.get_or_404(file_id)
        
        if not media_file.is_deleted:
            return jsonify({'error': 'File is not deleted'}), 400
        
        media_file.restore()
        db.session.commit()
        
        # Log activity
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        log_activity(
            user_id=user_data.get('user_id'),
            action='media_restored',
            resource_type='media',
            resource_id=file_id
        )
        
        return jsonify({
            'message': 'File restored successfully',
            'file': media_file.to_dict()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Restore media error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to restore file'}), 500


@media_bp.route('/<int:file_id>/permanent-delete', methods=['DELETE'])
@jwt_required()
@require_permission('media.delete')
def permanent_delete_media_file(file_id):
    """Permanently delete media file"""
    try:
        media_file = MediaFile.query.get_or_404(file_id)
        
        # Store info for logging
        filename = media_file.original_filename
        file_path = media_file.file_path
        thumbnail_path = media_file.thumbnail_path
        
        # Delete physical files
        try:
            full_path = os.path.join(current_app.root_path, file_path)
            if os.path.exists(full_path):
                os.remove(full_path)
            
            if thumbnail_path:
                thumb_full_path = os.path.join(
                    current_app.root_path,
                    thumbnail_path.lstrip('/')
                )
                if os.path.exists(thumb_full_path):
                    os.remove(thumb_full_path)
        except Exception as e:
            current_app.logger.error(f"File deletion error: {str(e)}")
        
        # Delete database record
        db.session.delete(media_file)
        db.session.commit()
        
        # Log activity
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        log_activity(
            user_id=user_data.get('user_id'),
            action='media_permanent_delete',
            resource_type='media',
            resource_id=file_id,
            data={'filename': filename}
        )
        
        return jsonify({'message': 'File permanently deleted'}), 200
        
    except Exception as e:
        current_app.logger.error(f"Permanent delete error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete file permanently'}), 500


@media_bp.route('/bulk-delete', methods=['POST'])
@jwt_required()
@require_permission('media.delete')
def bulk_delete_media():
    """Bulk delete media files"""
    try:
        data = request.get_json()
        file_ids = data.get('file_ids', [])
        permanent = data.get('permanent', False)
        
        if not file_ids:
            return jsonify({'error': 'No files selected'}), 400
        
        deleted_count = 0
        errors = []
        
        for file_id in file_ids:
            try:
                media_file = MediaFile.query.get(file_id)
                if media_file:
                    if permanent:
                        # Permanent delete
                        db.session.delete(media_file)
                    else:
                        # Soft delete
                        media_file.soft_delete()
                    deleted_count += 1
            except Exception as e:
                errors.append(f"File {file_id}: {str(e)}")
        
        db.session.commit()
        
        # Log activity
        identity = get_jwt_identity()
        user_data = json.loads(identity)
        log_activity(
            user_id=user_data.get('user_id'),
            action='media_bulk_delete',
            data={'count': deleted_count, 'permanent': permanent}
        )
        
        return jsonify({
            'message': f'{deleted_count} files deleted successfully',
            'deleted_count': deleted_count,
            'errors': errors
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Bulk delete error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Bulk delete failed'}), 500