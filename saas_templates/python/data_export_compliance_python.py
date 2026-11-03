# Repaired 2026-11-03: timezone-aware UTC times, always written with a Z (_iso_z), even for the naive values
#   SQLite returns; SQLAlchemy 2's declarative_base; the e-mail comes from the user's profile.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: the database, outgoing e-mail (mocked in tests).
import uuid
import json
import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Callable
import secrets
import boto3
from botocore.exceptions import ClientError
from sqlalchemy import (
    Column, String, DateTime, Enum, Text, UUID as PGUUID, create_engine, Integer, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from enum import Enum as PyEnum

Base = declarative_base()

class ExportRequestStatus(PyEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

class DeletionRequestStatus(PyEnum):
    PENDING = "pending"
    APPROVED = "approved"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

class ExportRequest(Base):
    __tablename__ = 'export_requests'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PGUUID(as_uuid=True), nullable=False)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(Enum(ExportRequestStatus), nullable=False, default=ExportRequestStatus.PENDING)
    format = Column(String(10), nullable=False)  # 'json' or 'csv'
    file_url = Column(Text, nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

class DeletionRequest(Base):
    __tablename__ = 'deletion_requests'
    
    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(PGUUID(as_uuid=True), nullable=False)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(Enum(DeletionRequestStatus), nullable=False, default=DeletionRequestStatus.PENDING)
    reason = Column(String(50), nullable=False)
    confirmation_token = Column(Text, nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    will_delete_at = Column(DateTime(timezone=True), nullable=True)

def get_export_requests_ddl() -> str:
    return """
    CREATE TABLE export_requests (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL,
        requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
        status VARCHAR(20) NOT NULL,
        format VARCHAR(10) NOT NULL,
        file_url TEXT,
        completed_at TIMESTAMP WITH TIME ZONE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """

def get_deletion_requests_ddl() -> str:
    return """
    CREATE TABLE deletion_requests (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL,
        requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
        status VARCHAR(20) NOT NULL,
        reason VARCHAR(50) NOT NULL,
        confirmation_token TEXT,
        deleted_at TIMESTAMP WITH TIME ZONE,
        will_delete_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    """

def _ensure_utc_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime is timezone-aware in UTC. If naive, assume UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def _iso_z(dt: datetime) -> str:
    """ISO 8601 in UTC with a Z suffix, also for the naive datetimes SQLite hands back."""
    return _ensure_utc_aware(dt).isoformat().replace('+00:00', 'Z')

class ComplianceManager:
    def __init__(
        self,
        db_session: Session,
        s3_client: boto3.client,
        email_service: Callable[[str, str, str], None],
        audit_logger: Callable[[str, uuid.UUID, Dict[str, Any]], None],
        export_user_data_func: Callable[[uuid.UUID], Dict[str, Any]],
        cascade_delete_func: Callable[[uuid.UUID], None],
        background_task_runner: Callable[[Callable, ...], None]
    ):
        self.db_session = db_session
        self.s3_client = s3_client
        self.email_service = email_service
        self.audit_logger = audit_logger
        self.export_user_data_func = export_user_data_func
        self.cascade_delete_func = cascade_delete_func
        self.background_task_runner = background_task_runner
        self.bucket_name = "compliance-exports"  # Should be configurable

    def request_data_export(self, user_id: uuid.UUID, format: str) -> Dict[str, Any]:
        if format not in ['json', 'csv']:
            raise ValueError("Format must be 'json' or 'csv'")
        
        export_id = uuid.uuid4()
        requested_at = datetime.now(timezone.utc)
        will_email_at = requested_at + timedelta(minutes=5)  # Estimated processing time
        
        export_request = ExportRequest(
            id=export_id,
            user_id=user_id,
            requested_at=requested_at,
            status=ExportRequestStatus.PENDING,
            format=format,
            expires_at=will_email_at + timedelta(days=7)  # Email will be sent with 7-day URL
        )
        self.db_session.add(export_request)
        self.db_session.commit()
        
        self.audit_logger(
            action='data_export_requested',
            user_id=user_id,
            details={'export_id': str(export_id), 'format': format}
        )
        
        self.background_task_runner(
            self._process_export,
            export_id
        )
        
        return {
            'success': True,
            'export_id': str(export_id),
            'status': ExportRequestStatus.PENDING.value,
            'will_email_at': _iso_z(will_email_at)
        }
    
    def _process_export(self, export_id: uuid.UUID):
        try:
            export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
            if not export_request or export_request.status != ExportRequestStatus.PENDING:
                return
            
            export_request.status = ExportRequestStatus.COMPLETED  # Temporary to prevent reprocessing
            self.db_session.commit()
            
            user_data = self.export_user_data_func(export_request.user_id)
            
            if export_request.format == 'json':
                file_content = json.dumps(user_data, indent=2, default=str)
                content_type = 'application/json'
            else:  # csv
                output = io.StringIO()
                writer = csv.writer(output)
                # Flatten the data for CSV - simplified example
                # In reality, this would need to handle nested structures
                writer.writerow(['category', 'key', 'value'])
                for category, data in user_data.items():
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    writer.writerow([category, k, v])
                            else:
                                writer.writerow([category, 'item', item])
                    elif isinstance(data, dict):
                        for k, v in data.items():
                            writer.writerow([category, k, v])
                    else:
                        writer.writerow([category, 'value', data])
                file_content = output.getvalue()
                content_type = 'text/csv'
            
            file_key = f"exports/{export_id}.{export_request.format}"
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=file_key,
                Body=file_content.encode('utf-8'),
                ContentType=content_type,
                ServerSideEncryption='AES256'
            )
            
            file_url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': file_key},
                ExpiresIn=7*24*60*60  # 7 days
            )
            
            completed_at = datetime.now(timezone.utc)
            export_request.file_url = file_url
            export_request.completed_at = completed_at
            export_request.expires_at = completed_at + timedelta(days=7)
            self.db_session.commit()
            
            # Get user email from data
            user_email = user_data.get('profile', {}).get('email', 'user@example.com')
            self.email_service(
                user_email,
                "Your data export is ready",
                f"Download your data export: {file_url}\nThis link expires in 7 days."
            )
            
            self.audit_logger(
                action='data_export_completed',
                user_id=export_request.user_id,
                details={'export_id': str(export_id), 'file_url': file_url}
            )
        except Exception as e:
            export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
            if export_request:
                export_request.status = ExportRequestStatus.FAILED
                export_request.completed_at = datetime.now(timezone.utc)
                self.db_session.commit()
            self.audit_logger(
                action='data_export_failed',
                user_id=export_request.user_id if export_request else None,
                details={'export_id': str(export_id), 'error': str(e)}
            )
    
    def get_export_status(self, export_id: uuid.UUID) -> Dict[str, Any]:
        export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
        if not export_request:
            raise ValueError("Export request not found")
        
        return {
            'export_id': str(export_request.id),
            'status': export_request.status.value,
            'file_url': export_request.file_url,
            'expires_at': _iso_z(export_request.expires_at) if export_request.expires_at else None,
            'requested_at': _iso_z(export_request.requested_at)
        }
    
    def request_account_deletion(self, user_id: uuid.UUID, reason: str) -> Dict[str, Any]:
        valid_reasons = ['user_requested', 'gdpr_request', 'gdpr_right_to_be_forgotten', 'other']
        if reason not in valid_reasons:
            raise ValueError(f"Reason must be one of {valid_reasons}")
        
        deletion_id = uuid.uuid4()
        requested_at = datetime.now(timezone.utc)
        will_delete_at = requested_at + timedelta(days=30)
        confirmation_token = secrets.token_urlsafe(32)
        
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=user_id,
            requested_at=requested_at,
            status=DeletionRequestStatus.PENDING,
            reason=reason,
            confirmation_token=confirmation_token,
            will_delete_at=will_delete_at
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        self.audit_logger(
            action='deletion_requested',
            user_id=user_id,
            details={'deletion_id': str(deletion_id), 'reason': reason}
        )
        
        # Send confirmation email
        user_email = self._get_user_email(user_id)
        confirmation_link = f"https://example.com/compliance/delete/{deletion_id}/confirm?token={confirmation_token}"
        self.email_service(
            user_email,
            "Confirm account deletion",
            f"Please confirm your deletion request by clicking: {confirmation_link}\nThis link will expire in 30 days."
        )
        
        self.background_task_runner(
            self._schedule_deletion,
            deletion_id
        )
        
        return {
            'success': True,
            'deletion_id': str(deletion_id),
            'status': DeletionRequestStatus.PENDING.value,
            'will_delete_at': _iso_z(will_delete_at)
        }
    
    def _get_user_email(self, user_id: uuid.UUID) -> str:
        user_data = self.export_user_data_func(user_id)
        return user_data.get('profile', {}).get('email', 'user@example.com')
    
    def _schedule_deletion(self, deletion_id: uuid.UUID):
        # In a real system, this would schedule a job for will_delete_at
        # For simplicity, we'll check periodically in background
        pass
    
    def confirm_deletion(self, deletion_id: uuid.UUID, confirmation_token: str) -> Dict[str, Any]:
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        if not deletion_request:
            raise ValueError("Deletion request not found")
        
        if deletion_request.confirmation_token != confirmation_token:
            raise ValueError("Invalid confirmation token")
        
        if deletion_request.status != DeletionRequestStatus.PENDING:
            raise ValueError("Deletion request is not pending")
        
        deletion_request.status = DeletionRequestStatus.APPROVED
        self.db_session.commit()
        
        self.audit_logger(
            action='deletion_confirmed',
            user_id=deletion_request.user_id,
            details={'deletion_id': str(deletion_id)}
        )
        
        return {
            'success': True,
            'deletion_scheduled_for': _iso_z(deletion_request.will_delete_at)
        }
    
    def cancel_deletion(self, deletion_id: uuid.UUID) -> Dict[str, Any]:
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        if not deletion_request:
            raise ValueError("Deletion request not found")
        
        if deletion_request.status != DeletionRequestStatus.PENDING and \
           deletion_request.status != DeletionRequestStatus.APPROVED:
            raise ValueError("Deletion request cannot be cancelled")
        
        # Ensure both datetimes are timezone-aware for comparison
        now_utc = datetime.now(timezone.utc)
        will_delete_at = _ensure_utc_aware(deletion_request.will_delete_at)
        
        if now_utc > will_delete_at:
            raise ValueError("Grace period has expired")
        
        deletion_request.status = DeletionRequestStatus.CANCELLED
        self.db_session.commit()
        
        self.audit_logger(
            action='deletion_cancelled',
            user_id=deletion_request.user_id,
            details={'deletion_id': str(deletion_id)}
        )
        
        return {
            'success': True,
            'status': DeletionRequestStatus.CANCELLED.value
        }
    
    def list_export_requests(self, admin_user_id: uuid.UUID, user_id: Optional[uuid.UUID] = None, status: Optional[ExportRequestStatus] = None) -> Dict[str, Any]:
        # Admin check would be done by caller
        query = self.db_session.query(ExportRequest)
        if user_id:
            query = query.filter(ExportRequest.user_id == user_id)
        if status:
            query = query.filter(ExportRequest.status == status)
        
        exports = query.all()
        return {
            'exports': [
                {
                    'export_id': str(e.id),
                    'user_id': str(e.user_id),
                    'requested_at': _iso_z(e.requested_at),
                    'status': e.status.value,
                    'format': e.format,
                    'file_url': e.file_url,
                    'completed_at': _iso_z(e.completed_at) if e.completed_at else None,
                    'expires_at': _iso_z(e.expires_at) if e.expires_at else None
                }
                for e in exports
            ],
            'total': len(exports)
        }
    
    def list_deletion_requests(self, admin_user_id: uuid.UUID, status: Optional[DeletionRequestStatus] = None) -> Dict[str, Any]:
        query = self.db_session.query(DeletionRequest)
        if status:
            query = query.filter(DeletionRequest.status == status)
        
        deletions = query.all()
        return {
            'deletions': [
                {
                    'deletion_id': str(d.id),
                    'user_id': str(d.user_id),
                    'requested_at': _iso_z(d.requested_at),
                    'status': d.status.value,
                    'reason': d.reason,
                    'will_delete_at': _iso_z(d.will_delete_at) if d.will_delete_at else None,
                    'deleted_at': _iso_z(d.deleted_at) if d.deleted_at else None
                }
                for d in deletions
            ],
            'total': len(deletions)
        }
