# Repaired 2026-11-03: timezone-aware UTC times, always written with a Z (_iso_z), even for the naive values
#   SQLite returns; SQLAlchemy 2's declarative_base; the e-mail comes from the user's profile.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: the database, outgoing e-mail (mocked in tests).
# Amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-05/12/13/14, spec amended after review on PR 19 and an
#   independent security review): statutory erasure has no grace period and runs on confirm; the confirmation
#   token is 32 random bytes kept only as its SHA-256, single-use, valid 24 h, bound to its deletion id and
#   compared in constant time; confirm/cancel act only on the caller's own request (else 404); the cascade runs
#   in one transaction (user rows, then 'user_deleted_cascade', then the injected audit eraser's
#   erase_subject LAST) and nulls deletion_requests.user_id; time comes from an injectable clock; the admin
#   lists check an injected is_admin.
import hashlib
import hmac
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
    # NULL once the deletion completes, so the row cannot re-identify erased audit entries (EXPORT-13).
    user_id = Column(PGUUID(as_uuid=True), nullable=True)
    requested_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(Enum(DeletionRequestStatus), nullable=False, default=DeletionRequestStatus.PENDING)
    reason = Column(String(50), nullable=False)
    # SHA-256 hex of the emailed token (never the token itself); NULL once spent or cancelled (EXPORT-14).
    confirmation_token = Column(Text, nullable=True)
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
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
    """Reference DDL for deletion_requests. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] user_id is nullable (NULL once completed, EXPORT-13)
    and the token is stored as its SHA-256 with token_expires_at (EXPORT-14). Touches nothing."""
    return """
    CREATE TABLE deletion_requests (
        id UUID PRIMARY KEY,
        user_id UUID,                      -- NULL once the deletion completes (EXPORT-13)
        requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
        status VARCHAR(20) NOT NULL,
        reason VARCHAR(50) NOT NULL,
        confirmation_token TEXT,           -- SHA-256 hex of the emailed token, NULL once spent
        token_expires_at TIMESTAMP WITH TIME ZONE,
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

STATUTORY_REASONS = ('gdpr_request', 'gdpr_right_to_be_forgotten')
GRACE_PERIOD = timedelta(days=30)
CONFIRMATION_TOKEN_TTL = timedelta(hours=24)
SIGNED_URL_TTL = timedelta(days=7)


class ComplianceError(ValueError):
    """A refused compliance request with an HTTP status and an error code.

    Subclasses ValueError so callers that caught ValueError keep working. Codes: not_found (404),
    invalid_confirmation_token (400, for a wrong, reused or expired token alike), deletion_not_pending (409),
    grace_period_over (409), admin_only (403). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Updated 2026-11-10 (Phase B.2, EXPORT-15): 404 is not_found, the expired-token 410 and cancel's
    cannot_cancel are gone (one answer in every language). Touches nothing."""

    def __init__(self, status: int, code: str, message: str = ""):
        """Hold the HTTP status and error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        self.status = status
        self.code = code
        super().__init__(message or code)


class UnconfiguredAuditEraser:
    """Default audit eraser: refuses, so a deletion never completes while the user's audit personal data stays.
    Inject the audit system's erase_subject (audit_logging.md). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
    (EXPORT-13). Touches nothing."""

    def erase_subject(self, user_id: uuid.UUID) -> None:
        """Always refuse: no eraser was configured. In: user_id. Out: never returns (RuntimeError)."""
        raise RuntimeError("no audit eraser is configured; inject the audit system's erase_subject")


def _token_hash(token: str) -> str:
    """SHA-256 hex of a confirmation token. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class ComplianceManager:
    def __init__(
        self,
        db_session: Session,
        s3_client: boto3.client,
        email_service: Callable[[str, str, str], None],
        audit_logger: Callable[[str, uuid.UUID, Dict[str, Any]], None],
        export_user_data_func: Callable[[uuid.UUID], Dict[str, Any]],
        cascade_delete_func: Callable[[uuid.UUID], None],
        background_task_runner: Callable[[Callable, ...], None],
        clock: Optional[Callable[[], datetime]] = None,
        audit_eraser: Any = None,
        is_admin: Optional[Callable[[uuid.UUID], bool]] = None,
    ):
        """Wire the compliance service to its collaborators.

        In: the SQLAlchemy session; S3 client; email_service(to, subject, body); audit_logger(action=, user_id=,
        details=); export_user_data_func(user_id); cascade_delete_func(user_id), which deletes the user's rows
        from every table except the audit tables, in this session WITHOUT committing; background_task_runner.
        Added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: clock (aware UTC datetime; default the wall clock);
        audit_eraser with erase_subject(user_id) (EXPORT-13; default refuses); is_admin(user_id) for the admin
        lists (default: nobody). The audit logger and cascade function must use this session so the cascade is
        one transaction. Touches nothing until called.
        """
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.audit_eraser = audit_eraser or UnconfiguredAuditEraser()
        self.is_admin = is_admin or (lambda user_id: False)
        self.db_session = db_session
        self.s3_client = s3_client
        self.email_service = email_service
        self.audit_logger = audit_logger
        self.export_user_data_func = export_user_data_func
        self.cascade_delete_func = cascade_delete_func
        self.background_task_runner = background_task_runner
        self.bucket_name = "compliance-exports"  # Should be configurable

    def request_data_export(self, user_id: uuid.UUID, format: str) -> Dict[str, Any]:
        """POST /compliance/export: record a pending export and hand it to the background runner.

        In: user_id (the verified caller), format 'json' | 'csv'. Out: {success, export_id, status 'pending', will_email_at}.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Times come from the injected clock. Touches: database, audit logger, background runner."""
        if format not in ['json', 'csv']:
            raise ValueError("Format must be 'json' or 'csv'")
        
        export_id = uuid.uuid4()
        requested_at = self.clock()
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
        """Build the export file, store it in S3 (encrypted), sign a 7-day download URL and email it.

        In: export_id. Out: None; a failure marks the export 'failed' and is audited. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Times come from the
        injected clock and the URL lifetime from SIGNED_URL_TTL (EXPORT-04). Touches: database, S3, email, audit logger."""
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
                ExpiresIn=int(SIGNED_URL_TTL.total_seconds())  # 7 days
            )
            
            completed_at = self.clock()
            export_request.file_url = file_url
            export_request.completed_at = completed_at
            export_request.expires_at = completed_at + SIGNED_URL_TTL
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
                export_request.completed_at = self.clock()
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
        """POST /compliance/delete for the authenticated user: record a pending deletion and email the token.

        In: user_id (the verified caller), reason. Out: {success, deletion_id, status 'pending', will_delete_at}.
        will_delete_at = requested_at + 30 days for user_requested / other (the user can cancel), and
        requested_at for a statutory reason (gdpr_request, gdpr_right_to_be_forgotten: no grace period).
        The token is 32 random bytes (URL-safe text) emailed once; only its SHA-256 is stored, valid 24 h.
        Nothing is deleted here. Why: EXPORT-05/12/14 as amended 2026-11-10 (every reason used to get 30 days,
        and the token was stored in plain text with no expiry). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: database (deletion_requests), email, audit logger.
        """
        valid_reasons = ['user_requested', 'gdpr_request', 'gdpr_right_to_be_forgotten', 'other']
        if reason not in valid_reasons:
            raise ValueError(f"Reason must be one of {valid_reasons}")
        
        deletion_id = uuid.uuid4()
        requested_at = self.clock()
        will_delete_at = requested_at if reason in STATUTORY_REASONS else requested_at + GRACE_PERIOD
        confirmation_token = secrets.token_urlsafe(32)
        
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=user_id,
            requested_at=requested_at,
            status=DeletionRequestStatus.PENDING,
            reason=reason,
            confirmation_token=_token_hash(confirmation_token),
            token_expires_at=requested_at + CONFIRMATION_TOKEN_TTL,
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
            f"Please confirm your deletion request by clicking: {confirmation_link}\nThis link will expire in 24 hours."
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

    def _own_deletion(self, user_id: uuid.UUID, deletion_id: uuid.UUID) -> DeletionRequest:
        """The caller's own deletion request, or ComplianceError 404 not_found (also for anyone else's, so
        another user's request is indistinguishable from none). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP
        (EXPORT-14; code renamed deletion_not_found -> not_found for EXPORT-15, Phase B.2).
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Spec clarification 3abb340: a COMPLETED request has no owner
        (user_id is NULL, EXPORT-13), so it is 404 not_found to every caller; a completed row that still names
        its user is treated the same. Touches: database (read)."""
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id, user_id=user_id).first()
        if deletion_request is None or user_id is None or deletion_request.status == DeletionRequestStatus.COMPLETED:
            raise ComplianceError(404, 'not_found', "Deletion request not found")
        return deletion_request

    @staticmethod
    def _refuse_if_closed(deletion_request: DeletionRequest) -> None:
        """Refuse a cancelled request: ComplianceError 409 deletion_not_pending. In: the caller's own request
        (a completed one never gets here: _own_deletion answers it 404). Out: None or the raise. Why: EXPORT-15
        (Phase B.2, as clarified in 3abb340: a cancelled request is 409, checked before the token, so a spent
        token on it does not read as a wrong token). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches nothing."""
        if deletion_request.status == DeletionRequestStatus.CANCELLED:
            raise ComplianceError(409, 'deletion_not_pending', "Deletion request is not pending")
    
    def confirm_deletion(self, user_id: uuid.UUID, deletion_id: uuid.UUID, confirmation_token: str) -> Dict[str, Any]:
        """POST /compliance/delete/:id/confirm for the authenticated user.

        In: user_id (the verified caller, never from the body), deletion_id, the emailed token. Checks, in order:
        the request is the caller's and not completed (else 404 not_found); it is not cancelled (else 409
        deletion_not_pending); the token's SHA-256 equals the stored hash in constant time and the token is under
        24 h old (else 400 invalid_confirmation_token: a wrong, reused (its hash is cleared once spent) or expired
        token all get that one answer); the request is pending (else 409 deletion_not_pending). Then pending ->
        approved and the token is spent. For a statutory reason the cascade runs before this returns (status
        completed, deleted_at = deletion_scheduled_for = now).
        Out: {success, deletion_scheduled_for}. Why: EXPORT-09/12/14 as amended 2026-11-10 (it compared the
        plain token with != and let anyone confirm anyone's request), and EXPORT-15 (Phase B.2, 2026-11-10: an
        expired token was 410 confirmation_token_expired, which told the caller which case it was).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: database, audit logger; for a statutory reason
        also S3, the cascade function and the audit eraser."""
        deletion_request = self._own_deletion(user_id, deletion_id)
        self._refuse_if_closed(deletion_request)
        stored = deletion_request.confirmation_token or ''
        supplied = _token_hash(confirmation_token if isinstance(confirmation_token, str) else '')
        token_matches = hmac.compare_digest(supplied.encode('ascii'), stored.encode('ascii', 'replace'))
        now = self.clock()
        expires = _ensure_utc_aware(deletion_request.token_expires_at)
        if not stored or not token_matches or expires is None or now >= expires:
            raise ComplianceError(400, 'invalid_confirmation_token', "Invalid confirmation token")
        if deletion_request.status != DeletionRequestStatus.PENDING:
            raise ComplianceError(409, 'deletion_not_pending', "Deletion request is not pending")

        statutory = deletion_request.reason in STATUTORY_REASONS
        deletion_request.status = DeletionRequestStatus.APPROVED
        deletion_request.confirmation_token = None  # single-use
        if statutory:
            deletion_request.will_delete_at = now
        self.db_session.commit()
        
        self.audit_logger(
            action='deletion_confirmed',
            user_id=deletion_request.user_id,
            details={'deletion_id': str(deletion_id)}
        )
        if statutory:
            self._run_cascade(deletion_request)
            return {'success': True, 'deletion_scheduled_for': _iso_z(now)}
        
        return {
            'success': True,
            'deletion_scheduled_for': _iso_z(deletion_request.will_delete_at)
        }
    
    def cancel_deletion(self, user_id: uuid.UUID, deletion_id: uuid.UUID) -> Dict[str, Any]:
        """DELETE /compliance/delete/:id for the authenticated user, within the grace period.

        In: user_id (the verified caller), deletion_id. Out: {success, status 'cancelled'}; ComplianceError 404
        not_found for anyone else's or a completed request, 409 deletion_not_pending (already cancelled) or 409
        grace_period_over (now >= will_delete_at). The token is spent. Why: EXPORT-06/14 (amended 2026-11-10:
        only the caller's own request) and EXPORT-15 (Phase B.2, 2026-11-10: a closed request was 409
        cannot_cancel; now deletion_not_pending, as for confirm). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Phase B.4 (af92d76, EXPORT-16): only a confirmed (approved)
        request is scheduled, so only it gets 409 grace_period_over from will_delete_at on (exactly at it included)
        and stays approved; a pending (unconfirmed) request can always be cancelled, even after will_delete_at (it
        was refused like a confirmed one).
        Touches: database, audit logger."""
        deletion_request = self._own_deletion(user_id, deletion_id)
        self._refuse_if_closed(deletion_request)
        
        # Ensure both datetimes are timezone-aware for comparison
        now_utc = self.clock()
        will_delete_at = _ensure_utc_aware(deletion_request.will_delete_at)
        
        # Phase B.4 (af92d76): a pending request is not scheduled, so the grace period binds only a confirmed one.
        if deletion_request.status == DeletionRequestStatus.APPROVED and now_utc >= will_delete_at:
            raise ComplianceError(409, 'grace_period_over', "Grace period has expired")
        
        deletion_request.status = DeletionRequestStatus.CANCELLED
        deletion_request.confirmation_token = None
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

    def process_due_deletions(self) -> int:
        """Run every approved deletion whose will_delete_at has passed (call from a scheduled job).

        Out: how many users were deleted. A cascade that fails is rolled back and re-raised, leaving the request
        approved so the next run retries it. Why: confirmed user_requested / other deletions had nothing that
        ever ran them. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (EXPORT-05/07). Touches: as _run_cascade."""
        now = self.clock()
        due = [d for d in self.db_session.query(DeletionRequest)
               .filter(DeletionRequest.status == DeletionRequestStatus.APPROVED, DeletionRequest.user_id.isnot(None))
               .all() if _ensure_utc_aware(d.will_delete_at) <= now]
        for deletion_request in due:
            self._run_cascade(deletion_request)
        return len(due)

    def _run_cascade(self, deletion_request: DeletionRequest) -> None:
        """Delete one user, in ONE transaction and in this order (spec, IMPLEMENTATION "Cascade delete"):

        S3 export files are removed first (outside the transaction: a storage error stops before anything is
        deleted). Then (1) cascade_delete_func(user_id) deletes the user's rows from every table except the audit
        tables, and the user's export_requests rows are deleted; (2) audit_logger logs 'user_deleted_cascade'
        with the user as subject; the request becomes completed (deleted_at = now) and user_id is set NULL on
        every deletion request of this user; (3) audit_eraser.erase_subject(user_id) is called LAST; then commit.
        Nothing logs this user afterwards. Any error rolls the transaction back and is re-raised.
        In: an approved deletion request. Out: None. Why: EXPORT-07/08/13 as amended 2026-11-10 (nothing erased
        the user's audit personal data). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: S3 (deletes objects), database, the cascade function, audit logger and audit eraser."""
        user_id = deletion_request.user_id
        exports = self.db_session.query(ExportRequest).filter_by(user_id=user_id).all()
        for export in exports:
            if export.file_url:
                self.s3_client.delete_object(Bucket=self.bucket_name, Key=f"exports/{export.id}.{export.format}")
        now = self.clock()
        try:
            self.cascade_delete_func(user_id)
            removed_exports = self.db_session.query(ExportRequest).filter_by(user_id=user_id).delete()
            self.audit_logger(
                action='user_deleted_cascade',
                user_id=user_id,
                details={'deletion_id': str(deletion_request.id), 'export_requests': removed_exports}
            )
            deletion_request.status = DeletionRequestStatus.COMPLETED
            deletion_request.deleted_at = now
            for other in self.db_session.query(DeletionRequest).filter_by(user_id=user_id).all():
                if other.status in (DeletionRequestStatus.PENDING, DeletionRequestStatus.APPROVED):
                    other.status = DeletionRequestStatus.CANCELLED
                other.confirmation_token = None
                other.user_id = None
            self.audit_eraser.erase_subject(user_id)
            self.db_session.commit()
        except BaseException:
            self.db_session.rollback()
            raise

    def _require_admin(self, admin_user_id: uuid.UUID) -> None:
        """ComplianceError 403 admin_only unless the injected is_admin says the verified caller is an admin.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (it was "checked by the caller", so easy to forget).
        Touches: whatever is_admin reads."""
        if admin_user_id is None or not self.is_admin(admin_user_id):
            raise ComplianceError(403, 'admin_only', "Admin only")
    
    def list_export_requests(self, admin_user_id: uuid.UUID, user_id: Optional[uuid.UUID] = None, status: Optional[ExportRequestStatus] = None) -> Dict[str, Any]:
        """GET /admin/compliance/exports (admin only; 403 admin_only otherwise). Filters by user and status.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The admin check moved in here. Touches: database (read)."""
        self._require_admin(admin_user_id)
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
        """GET /admin/compliance/deletions (admin only; 403 admin_only otherwise). Filters by status.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The admin check moved in here. Touches: database (read)."""
        self._require_admin(admin_user_id)
        query = self.db_session.query(DeletionRequest)
        if status:
            query = query.filter(DeletionRequest.status == status)
        
        deletions = query.all()
        return {
            'deletions': [
                {
                    'deletion_id': str(d.id),
                    'user_id': str(d.user_id) if d.user_id else None,
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
