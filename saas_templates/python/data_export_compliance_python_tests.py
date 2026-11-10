# Tests updated with the fix 2026-11-03: timezone-aware UTC times, always written with a Z (_iso_z), even for the naive values
#   SQLite returns; SQLAlchemy 2's declarative_base; the e-mail comes from the user's profile.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: the database, outgoing e-mail (mocked in tests).
import unittest
from unittest.mock import Mock, patch, MagicMock, ANY
import uuid
import json
import csv
import io
from datetime import datetime, timedelta, timezone
import boto3
from moto import mock_s3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

# Add the current directory to the path to import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_export_compliance_python import (
    ComplianceManager,
    ExportRequest,
    DeletionRequest,
    Base,
    get_export_requests_ddl,
    get_deletion_requests_ddl,
    ExportRequestStatus,
    DeletionRequestStatus,
    ComplianceError,
)
from sqlalchemy import text

T0 = datetime(2026, 11, 10, 9, 0, 0, tzinfo=timezone.utc)


def _hash(token):
    """SHA-256 hex of a token, as the module stores it. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    import hashlib
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

class TestComplianceManager(unittest.TestCase):
    def setUp(self):
        # Create in-memory SQLite database
        """In-memory database, mocked S3, mocked collaborators, a fixed clock, a fake audit eraser and is_admin. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.db_session = Session()
        
        # Mock S3
        self.s3_mock = mock_s3()
        self.s3_mock.start()
        self.s3_client = boto3.client('s3', region_name='us-east-1')
        self.s3_client.create_bucket(Bucket='compliance-exports')
        
        # Mock services
        self.email_service = Mock()
        self.audit_logger = Mock()
        self.export_user_data_func = Mock()
        self.cascade_delete_func = Mock()
        # Background task runner that captures calls but doesn't execute them
        self.background_task_runner = Mock()
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] New collaborators: an injected clock, a fake audit eraser
        # (EXPORT-13) and is_admin for the admin lists (EXPORT-10).
        self.now = [T0]
        self.audit_eraser = Mock()
        self.admin_id = uuid.uuid4()
        
        # Initialize compliance manager
        self.compliance = ComplianceManager(
            clock=lambda: self.now[0],
            audit_eraser=self.audit_eraser,
            is_admin=lambda uid: uid == self.admin_id,
            db_session=self.db_session,
            s3_client=self.s3_client,
            email_service=self.email_service,
            audit_logger=self.audit_logger,
            export_user_data_func=self.export_user_data_func,
            cascade_delete_func=self.cascade_delete_func,
            background_task_runner=self.background_task_runner
        )
        
        # Set up test user data
        self.test_user_id = uuid.uuid4()
        self.export_user_data_func.return_value = {
            'profile': {
                'id': str(self.test_user_id),
                'email': 'test@example.com',
                'name': 'Test User',
                'created_at': '2026-01-01T00:00:00Z',
                'tier': 'premium',
                'status': 'active'
            },
            'sessions': [
                {'ip': '192.168.1.1', 'device_info': 'Chrome on Windows'},
                {'ip': '192.168.1.2', 'device_info': 'Safari on iOS'}
            ],
            'activity': [
                {'action': 'login', 'timestamp': '2026-09-01T10:00:00Z'},
                {'action': 'purchase', 'timestamp': '2026-09-02T11:00:00Z'}
            ],
            'files': [
                {'name': 'document.pdf', 'size': 1024},
                {'name': 'photo.jpg', 'size': 2048}
            ],
            'preferences': {
                'notifications': {'email': True, 'sms': False},
                'theme': 'dark',
                'language': 'en'
            },
            'transactions': [
                {'type': 'invoice', 'amount': 99.99, 'date': '2026-09-01'},
                {'type': 'payment', 'amount': 99.99, 'date': '2026-09-02'}
            ],
            'audit_trail': [
                {'action': 'profile_update', 'timestamp': '2026-09-01T12:00:00Z'},
                {'action': 'password_change', 'timestamp': '2026-09-02T13:00:00Z'}
            ]
        }
    
    def tearDown(self):
        self.s3_mock.stop()
        self.db_session.close()
    
    # EXPORT-01
    def test_export_json_format(self):
        result = self.compliance.request_data_export(self.test_user_id, 'json')
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'pending')
        self.assertIn('export_id', result)
        export_id = uuid.UUID(result['export_id'])
        
        # Check that export request was created
        export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
        self.assertIsNotNone(export_request)
        self.assertEqual(export_request.status, ExportRequestStatus.PENDING)
        self.assertEqual(export_request.format, 'json')
        
        # Check audit log
        self.audit_logger.assert_called_with(
            action='data_export_requested',
            user_id=self.test_user_id,
            details={'export_id': str(export_id), 'format': 'json'}
        )
        
        # Check background task was scheduled
        self.background_task_runner.assert_called()
        args, kwargs = self.background_task_runner.call_args
        self.assertEqual(args[0], self.compliance._process_export)
        self.assertEqual(args[1], export_id)
    
    # EXPORT-01
    def test_export_csv_format(self):
        """A CSV export is recorded, produced and readable.
        In: the test fixtures. Out: assertions. Why: EXPORT-01. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: the file is now produced and read back.
        Touches: the test database, mocked S3."""
        result = self.compliance.request_data_export(self.test_user_id, 'csv')
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'pending')
        export_id = uuid.UUID(result['export_id'])
        
        export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
        self.assertEqual(export_request.format, 'csv')
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] EXPORT-01: the CSV export is also produced and readable.
        self.compliance._process_export(export_id)
        obj = self.s3_client.get_object(Bucket='compliance-exports', Key=f"exports/{export_id}.csv")
        self.assertEqual(obj['ContentType'], 'text/csv')
        rows = list(csv.reader(io.StringIO(obj['Body'].read().decode('utf-8'))))
        self.assertEqual(rows[0], ['category', 'key', 'value'])
        self.assertIn(['profile', 'email', 'test@example.com'], rows)
    
    def test_export_invalid_format(self):
        with self.assertRaises(ValueError):
            self.compliance.request_data_export(self.test_user_id, 'xml')
    
    # EXPORT-04
    # EXPORT-03
    # EXPORT-02
    def test_export_processing(self):
        """The JSON export holds every category, is emailed as a 7-day signed URL that reads the file.
        In: the test fixtures. Out: assertions. Why: EXPORT-02/03/04. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: URL lifetime, categories and file contents checked.
        Touches: the test database, mocked S3."""
        export_id = uuid.uuid4()
        requested_at = datetime.now(timezone.utc)
        export_request = ExportRequest(
            id=export_id,
            user_id=self.test_user_id,
            requested_at=requested_at,
            status=ExportRequestStatus.PENDING,
            format='json',
            expires_at=requested_at + timedelta(days=7)
        )
        self.db_session.add(export_request)
        self.db_session.commit()
        
        # Process the export
        self.compliance._process_export(export_id)
        
        # Check export request updated
        export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
        self.assertEqual(export_request.status, ExportRequestStatus.COMPLETED)
        self.assertIsNotNone(export_request.file_url)
        self.assertIsNotNone(export_request.completed_at)
        self.assertIsNotNone(export_request.expires_at)
        
        # Check S3 object exists
        objects = self.s3_client.list_objects_v2(Bucket='compliance-exports')
        self.assertEqual(len(objects['Contents']), 1)
        key = objects['Contents'][0]['Key']
        self.assertTrue(key.startswith('exports/'))
        self.assertTrue(key.endswith('.json'))
        
        # Check email sent
        self.email_service.assert_called()
        args, kwargs = self.email_service.call_args
        self.assertEqual(args[0], 'test@example.com')  # to
        self.assertIn('Your data export is ready', args[1])  # subject
        self.assertIn('https://', args[2])  # body contains URL
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] EXPORT-04: the signed URL is the one emailed, it reads
        # the stored file, and it and the record expire after 7 days.
        self.assertIn(export_request.file_url, args[2])
        import time
        from urllib.parse import urlparse, parse_qs
        query = parse_qs(urlparse(export_request.file_url).query)
        if 'X-Amz-Expires' in query:  # SigV4 URL
            self.assertEqual(query['X-Amz-Expires'], ['604800'])
        else:  # SigV2 URL: an absolute expiry, about 7 days from the (wall-clock) signing time
            self.assertAlmostEqual(int(query['Expires'][0]) - time.time(), 604800, delta=120)
        self.assertEqual(export_request.expires_at.replace(tzinfo=timezone.utc), T0 + timedelta(days=7))
        body = self.s3_client.get_object(Bucket='compliance-exports', Key=key)['Body'].read()
        self.assertEqual(json.loads(body)['profile']['email'], 'test@example.com')
        # EXPORT-02: every data category is in the file
        self.assertEqual(set(json.loads(body)), {'profile', 'sessions', 'activity', 'files', 'preferences',
                                                 'transactions', 'audit_trail'})
        
        # Check audit log
        self.audit_logger.assert_any_call(
            action='data_export_completed',
            user_id=self.test_user_id,
            details={'export_id': str(export_id), 'file_url': ANY}
        )
    
    def test_export_status(self):
        export_id = uuid.uuid4()
        requested_at = datetime.now(timezone.utc)
        export_request = ExportRequest(
            id=export_id,
            user_id=self.test_user_id,
            requested_at=requested_at,
            status=ExportRequestStatus.COMPLETED,
            format='json',
            file_url='https://example.com/file.json',
            completed_at=requested_at + timedelta(minutes=5),
            expires_at=requested_at + timedelta(days=7)
        )
        self.db_session.add(export_request)
        self.db_session.commit()
        
        status = self.compliance.get_export_status(export_id)
        
        self.assertEqual(status['export_id'], str(export_id))
        self.assertEqual(status['status'], 'completed')
        self.assertEqual(status['file_url'], 'https://example.com/file.json')
        self.assertIsNotNone(status['expires_at'])
        self.assertIsNotNone(status['requested_at'])
    
    # ----- deletion (amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) -----
    # The deletion tests below were changed for the amended spec: confirm/cancel take the verified caller's
    # user_id first (anyone else's request is 404), the stored token is its SHA-256 with a 24 h expiry, and
    # time comes from the injected clock.

    def _make_deletion(self, token='valid_token', status=DeletionRequestStatus.PENDING, reason='user_requested',
                       user_id=None, will_delete_at=None, token_expires_at=None):
        """Insert a deletion request whose token is `token` (stored hashed). Out: its id.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database."""
        deletion_id = uuid.uuid4()
        self.db_session.add(DeletionRequest(
            id=deletion_id,
            user_id=user_id or self.test_user_id,
            requested_at=self.now[0],
            status=status,
            reason=reason,
            confirmation_token=_hash(token) if token else None,
            token_expires_at=token_expires_at or self.now[0] + timedelta(hours=24),
            will_delete_at=will_delete_at or self.now[0] + timedelta(days=30),
        ))
        self.db_session.commit()
        return deletion_id

    def _emailed_token(self):
        """The token from the last confirmation email. Touches nothing."""
        body = self.email_service.call_args[0][2]
        return body.split('token=')[1].split()[0]

    # EXPORT-05
    # EXPORT-11
    def test_request_deletion(self):
        """user_requested: will_delete_at = +30 days, token emailed once and stored hashed, nothing runs before the grace ends.
        In: the test fixtures. Out: assertions. Why: EXPORT-05/11. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: hashed token, grace period enforced through process_due_deletions.
        Touches: in-memory SQLite only, mocks."""
        reason = 'user_requested'
        result = self.compliance.request_account_deletion(self.test_user_id, reason)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'pending')
        self.assertIn('deletion_id', result)
        self.assertEqual(result['will_delete_at'], '2026-12-10T09:00:00Z')  # requested_at + 30 days
        deletion_id = uuid.UUID(result['deletion_id'])
        
        # Check deletion request created
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        self.assertIsNotNone(deletion_request)
        self.assertEqual(deletion_request.status, DeletionRequestStatus.PENDING)
        self.assertEqual(deletion_request.reason, reason)
        self.assertIsNotNone(deletion_request.confirmation_token)
        self.assertIsNotNone(deletion_request.will_delete_at)
        
        # Check audit log
        self.audit_logger.assert_called_with(
            action='deletion_requested',
            user_id=self.test_user_id,
            details={'deletion_id': str(deletion_id), 'reason': reason}
        )
        
        # Check email sent: the link carries the raw token; only its SHA-256 is stored
        self.email_service.assert_called()
        args, kwargs = self.email_service.call_args
        self.assertEqual(args[0], 'test@example.com')
        self.assertIn('Confirm account deletion', args[1])
        self.assertIn(str(deletion_id), args[2])
        token = self._emailed_token()
        self.assertEqual(len(token), 43)  # 32 random bytes, URL-safe base64
        self.assertNotIn(token, deletion_request.confirmation_token)
        self.assertEqual(deletion_request.confirmation_token, _hash(token))
        # grace period: nothing runs before will_delete_at, even once confirmed
        self.compliance.confirm_deletion(self.test_user_id, deletion_id, token)
        self.now[0] = T0 + timedelta(days=30) - timedelta(seconds=1)
        self.assertEqual(self.compliance.process_due_deletions(), 0)
        self.cascade_delete_func.assert_not_called()
        self.now[0] = T0 + timedelta(days=30)
        self.assertEqual(self.compliance.process_due_deletions(), 1)
        self.cascade_delete_func.assert_called_once_with(self.test_user_id)
    
    # EXPORT-12
    def test_statutory_deletion_has_no_grace_period(self):
        """gdpr_request and gdpr_right_to_be_forgotten: will_delete_at = requested_at, and confirm() runs the
        cascade before it returns (status completed, deleted_at = now). Why: EXPORT-12 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database and mocks."""
        for reason in ('gdpr_request', 'gdpr_right_to_be_forgotten'):
            user_id = uuid.uuid4()
            self.cascade_delete_func.reset_mock()
            result = self.compliance.request_account_deletion(user_id, reason)
            self.assertEqual(result['will_delete_at'], '2026-11-10T09:00:00Z')
            self.cascade_delete_func.assert_not_called()  # nothing deleted before confirm
            self.now[0] = T0 + timedelta(hours=2)
            confirmed = self.compliance.confirm_deletion(user_id, uuid.UUID(result['deletion_id']), self._emailed_token())
            self.assertEqual(confirmed, {'success': True, 'deletion_scheduled_for': '2026-11-10T11:00:00Z'})
            self.cascade_delete_func.assert_called_once_with(user_id)
            row = self.db_session.query(DeletionRequest).filter_by(id=uuid.UUID(result['deletion_id'])).first()
            self.assertEqual(row.status, DeletionRequestStatus.COMPLETED)
            self.assertEqual(row.deleted_at.replace(tzinfo=timezone.utc), T0 + timedelta(hours=2))
            self.now[0] = T0
    
    def test_request_deletion_invalid_reason(self):
        with self.assertRaises(ValueError):
            self.compliance.request_account_deletion(self.test_user_id, 'invalid_reason')
    
    # EXPORT-09
    def test_confirm_deletion_success(self):
        """The owner's valid token approves the request and is spent.
        In: the test fixtures. Out: assertions. Why: EXPORT-09. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: caller user_id, hashed token.
        Touches: in-memory SQLite only."""
        deletion_id = self._make_deletion(token='valid_token')
        
        # Confirm deletion
        result = self.compliance.confirm_deletion(self.test_user_id, deletion_id, 'valid_token')
        
        self.assertTrue(result['success'])
        self.assertEqual(result['deletion_scheduled_for'], '2026-12-10T09:00:00Z')
        
        # Check deletion request updated
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        self.assertEqual(deletion_request.status, DeletionRequestStatus.APPROVED)
        self.assertIsNone(deletion_request.confirmation_token)  # spent
        
        # Check audit log
        self.audit_logger.assert_called_with(
            action='deletion_confirmed',
            user_id=self.test_user_id,
            details={'deletion_id': str(deletion_id)}
        )
    
    # EXPORT-14
    def test_confirm_deletion_invalid_token(self):
        """A wrong token is 400 invalid_confirmation_token and changes nothing.
        In: the test fixtures. Out: assertions. Why: EXPORT-14. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: caller user_id, error code.
        Touches: in-memory SQLite only."""
        deletion_id = self._make_deletion(token='valid_token')
        
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.confirm_deletion(self.test_user_id, deletion_id, 'invalid_token')
        self.assertEqual((cm.exception.status, cm.exception.code), (400, 'invalid_confirmation_token'))
        self.assertEqual(self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first().status,
                         DeletionRequestStatus.PENDING)
    
    # EXPORT-14
    def test_confirmation_token_reused_expired_or_other_users_request_refused(self):
        """Nothing is deleted before confirm; a reused token, a token over 24 h old and another user's request
        (404 for confirm and cancel) are all refused. Why: EXPORT-14 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database and mocks."""
        result = self.compliance.request_account_deletion(self.test_user_id, 'gdpr_request')
        deletion_id = uuid.UUID(result['deletion_id'])
        token = self._emailed_token()
        self.cascade_delete_func.assert_not_called()
        intruder = uuid.uuid4()
        for call in (lambda: self.compliance.confirm_deletion(intruder, deletion_id, token),
                     lambda: self.compliance.cancel_deletion(intruder, deletion_id)):
            with self.assertRaises(ComplianceError) as cm:
                call()
            self.assertEqual((cm.exception.status, cm.exception.code), (404, 'deletion_not_found'))
        self.now[0] = T0 + timedelta(hours=24)
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.confirm_deletion(self.test_user_id, deletion_id, token)
        self.assertEqual((cm.exception.status, cm.exception.code), (410, 'confirmation_token_expired'))
        self.cascade_delete_func.assert_not_called()

        other = self._make_deletion(token='once', reason='user_requested')
        self.compliance.confirm_deletion(self.test_user_id, other, 'once')
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.confirm_deletion(self.test_user_id, other, 'once')
        self.assertEqual((cm.exception.status, cm.exception.code), (400, 'invalid_confirmation_token'))
        self.cascade_delete_func.assert_not_called()
    
    def test_confirm_deletion_wrong_status(self):
        """Confirming a non-pending request is 409 deletion_not_pending.
        In: the test fixtures. Out: assertions. Why: EXPORT-09. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: caller user_id, error code.
        Touches: in-memory SQLite only."""
        deletion_id = self._make_deletion(token='token', status=DeletionRequestStatus.APPROVED)
        
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.confirm_deletion(self.test_user_id, deletion_id, 'token')
        self.assertEqual(cm.exception.code, 'deletion_not_pending')
    
    # EXPORT-06
    def test_cancel_deletion_within_grace_period(self):
        """The owner cancels within the grace period and nothing is deleted later.
        In: the test fixtures. Out: assertions. Why: EXPORT-06. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: caller user_id, clock.
        Touches: in-memory SQLite only."""
        deletion_id = self._make_deletion(token='token')
        self.now[0] = T0 + timedelta(days=29)
        
        # Cancel deletion
        result = self.compliance.cancel_deletion(self.test_user_id, deletion_id)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'cancelled')
        
        # Check deletion request updated
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        self.assertEqual(deletion_request.status, DeletionRequestStatus.CANCELLED)
        
        # Check audit log
        self.audit_logger.assert_called_with(
            action='deletion_cancelled',
            user_id=self.test_user_id,
            details={'deletion_id': str(deletion_id)}
        )
        self.now[0] = T0 + timedelta(days=31)
        self.assertEqual(self.compliance.process_due_deletions(), 0)
        self.cascade_delete_func.assert_not_called()
    
    def test_cancel_deletion_after_grace_period(self):
        """Cancelling after will_delete_at is 409 grace_period_over.
        In: the test fixtures. Out: assertions. Why: EXPORT-06. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: caller user_id, error code.
        Touches: in-memory SQLite only."""
        deletion_id = self._make_deletion(token='token', will_delete_at=T0 - timedelta(days=1))
        
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.cancel_deletion(self.test_user_id, deletion_id)
        self.assertEqual(cm.exception.code, 'grace_period_over')
    
    def test_cancel_deletion_wrong_status(self):
        """Cancelling a completed request is 409 cannot_cancel.
        In: the test fixtures. Out: assertions. Why: EXPORT-06. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: caller user_id, error code.
        Touches: in-memory SQLite only."""
        deletion_id = self._make_deletion(token='token', status=DeletionRequestStatus.COMPLETED)
        
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.cancel_deletion(self.test_user_id, deletion_id)
        self.assertEqual(cm.exception.code, 'cannot_cancel')

    def _real_tables(self):
        """Create user tables and an audit_log in the test database and wire a real cascade function and audit
        logger that use the manager's session (no commit). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: the test database."""
        for ddl in ("CREATE TABLE user_sessions (id INTEGER PRIMARY KEY, user_id TEXT)",
                    "CREATE TABLE api_keys (id INTEGER PRIMARY KEY, user_id TEXT)",
                    "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, user_id TEXT, action TEXT)"):
            self.db_session.execute(text(ddl))
        uid = str(self.test_user_id)
        for table in ('user_sessions', 'user_sessions', 'api_keys'):
            self.db_session.execute(text(f"INSERT INTO {table} (user_id) VALUES (:u)"), {'u': uid})
        self.db_session.execute(text("INSERT INTO audit_log (user_id, action) VALUES (:u, 'login')"), {'u': uid})
        self.db_session.commit()

        def cascade(user_id):
            for table in ('user_sessions', 'api_keys'):
                self.db_session.execute(text(f"DELETE FROM {table} WHERE user_id = :u"), {'u': str(user_id)})

        def audit(action, user_id, details):
            self.db_session.execute(text("INSERT INTO audit_log (user_id, action) VALUES (:u, :a)"),
                                    {'u': str(user_id) if user_id else None, 'a': action})

        self.compliance.cascade_delete_func = cascade
        self.compliance.audit_logger = audit

    def _count(self, sql):
        """Run a COUNT query with :u bound to the test user's id. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return self.db_session.execute(text(sql), {'u': str(self.test_user_id)}).scalar()

    # EXPORT-07
    def test_cascade_deletes_user_rows_and_export_files(self):
        """The cascade deletes the user's sessions, api keys, export requests and export files, in one
        transaction. Why: EXPORT-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: the test database and mocked S3."""
        self._real_tables()
        export = self.compliance.request_data_export(self.test_user_id, 'json')
        self.compliance._process_export(uuid.UUID(export['export_id']))
        self.assertEqual(len(self.s3_client.list_objects_v2(Bucket='compliance-exports').get('Contents', [])), 1)
        deletion_id = self._make_deletion(token='t', reason='gdpr_request')
        self.compliance.confirm_deletion(self.test_user_id, deletion_id, 't')
        self.assertEqual(self._count("SELECT COUNT(*) FROM user_sessions WHERE user_id = :u"), 0)
        self.assertEqual(self._count("SELECT COUNT(*) FROM api_keys WHERE user_id = :u"), 0)
        self.assertEqual(self.db_session.query(ExportRequest).filter_by(user_id=self.test_user_id).count(), 0)
        self.assertEqual(self.s3_client.list_objects_v2(Bucket='compliance-exports').get('Contents', []), [])

    # EXPORT-08
    def test_cascade_keeps_the_audit_log(self):
        """After the cascade, the user's audit_log rows are still there, including 'user_deleted_cascade'
        (only the audit eraser touches audit data). Why: EXPORT-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: the test database."""
        self._real_tables()
        deletion_id = self._make_deletion(token='t', reason='gdpr_right_to_be_forgotten')
        self.compliance.confirm_deletion(self.test_user_id, deletion_id, 't')
        actions = [r[0] for r in self.db_session.execute(
            text("SELECT action FROM audit_log WHERE user_id = :u ORDER BY id"), {'u': str(self.test_user_id)})]
        self.assertEqual(actions, ['login', 'deletion_confirmed', 'user_deleted_cascade'])

    # EXPORT-13
    def test_cascade_order_and_eraser_last(self):
        """Order: the user's rows are deleted, 'user_deleted_cascade' is logged, then erase_subject(user_id) is
        called LAST with nothing logged after it; deletion_requests.user_id is NULL once completed; an eraser
        failure rolls everything back. Why: EXPORT-13 (amended 2026-11-10).
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: the test database and mocks."""
        calls = []
        self.compliance.cascade_delete_func = lambda uid: calls.append(('cascade', uid))
        self.compliance.audit_logger = lambda action, user_id, details: calls.append(('log', action))
        self.audit_eraser.erase_subject.side_effect = lambda uid: calls.append(('erase', uid))
        deletion_id = self._make_deletion(token='t', reason='gdpr_request')
        self.compliance.confirm_deletion(self.test_user_id, deletion_id, 't')
        self.assertEqual(calls, [('log', 'deletion_confirmed'), ('cascade', self.test_user_id),
                                 ('log', 'user_deleted_cascade'), ('erase', self.test_user_id)])
        row = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        self.assertEqual(row.status, DeletionRequestStatus.COMPLETED)
        self.assertIsNone(row.user_id)

        # an eraser that fails rolls the cascade back: the request stays approved for the next run
        user2 = uuid.uuid4()
        self.audit_eraser.erase_subject.side_effect = RuntimeError("audit store down")
        d2 = self._make_deletion(token='t2', reason='user_requested', user_id=user2)
        self.compliance.confirm_deletion(user2, d2, 't2')
        self.now[0] = T0 + timedelta(days=30)
        with self.assertRaises(RuntimeError):
            self.compliance.process_due_deletions()
        row2 = self.db_session.query(DeletionRequest).filter_by(id=d2).first()
        self.assertEqual((row2.status, row2.user_id), (DeletionRequestStatus.APPROVED, user2))

    # EXPORT-10
    def test_list_export_requests(self):
        # Create test exports
        """An admin lists exports filtered by user and status; a non-admin gets 403.
        In: the test fixtures. Out: assertions. Why: EXPORT-10. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: is_admin is checked inside.
        Touches: in-memory SQLite only."""
        export1 = ExportRequest(
            id=uuid.uuid4(),
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=ExportRequestStatus.COMPLETED,
            format='json',
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        export2 = ExportRequest(
            id=uuid.uuid4(),
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=ExportRequestStatus.PENDING,
            format='csv',
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        export3 = ExportRequest(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),  # Different user
            requested_at=datetime.now(timezone.utc),
            status=ExportRequestStatus.COMPLETED,
            format='json',
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        self.db_session.add_all([export1, export2, export3])
        self.db_session.commit()
        
        # [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The lists now check is_admin themselves: a random id is
        # refused 403 and the configured admin id is used below.
        with self.assertRaises(ComplianceError) as cm:
            self.compliance.list_export_requests(admin_user_id=uuid.uuid4())
        self.assertEqual((cm.exception.status, cm.exception.code), (403, 'admin_only'))

        # List all exports for test user
        result = self.compliance.list_export_requests(admin_user_id=self.admin_id, user_id=self.test_user_id)
        
        self.assertEqual(result['total'], 2)
        export_ids = [str(e['export_id']) for e in result['exports']]
        self.assertIn(str(export1.id), export_ids)
        self.assertIn(str(export2.id), export_ids)
        self.assertNotIn(str(export3.id), export_ids)
        
        # List completed exports
        result = self.compliance.list_export_requests(admin_user_id=self.admin_id, status=ExportRequestStatus.COMPLETED)
        self.assertEqual(result['total'], 2)  # export1 and export3
        
        # List pending exports for test user
        result = self.compliance.list_export_requests(admin_user_id=self.admin_id, user_id=self.test_user_id, status=ExportRequestStatus.PENDING)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['exports'][0]['export_id'], str(export2.id))
    
    # EXPORT-10
    def test_list_deletion_requests(self):
        """An admin lists deletions filtered by status; a non-admin gets 403.
        In: the test fixtures. Out: assertions. Why: EXPORT-10. Updated 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP: is_admin, hashed tokens.
        Touches: in-memory SQLite only."""
        deletion1 = self._make_deletion(token='token1', reason='gdpr_request')
        deletion2 = self._make_deletion(token='token2', status=DeletionRequestStatus.APPROVED)
        deletion3 = self._make_deletion(token='token3', reason='other', user_id=uuid.uuid4())
        
        with self.assertRaises(ComplianceError):
            self.compliance.list_deletion_requests(admin_user_id=self.test_user_id)

        # List all deletions
        result = self.compliance.list_deletion_requests(admin_user_id=self.admin_id)
        
        self.assertEqual(result['total'], 3)
        deletion_ids = [str(d['deletion_id']) for d in result['deletions']]
        self.assertIn(str(deletion1), deletion_ids)
        self.assertIn(str(deletion2), deletion_ids)
        self.assertIn(str(deletion3), deletion_ids)
        
        # List pending deletions
        result = self.compliance.list_deletion_requests(admin_user_id=self.admin_id, status=DeletionRequestStatus.PENDING)
        self.assertEqual(result['total'], 2)  # deletion1 and deletion3
        
        # List approved deletions
        result = self.compliance.list_deletion_requests(admin_user_id=self.admin_id, status=DeletionRequestStatus.APPROVED)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['deletions'][0]['deletion_id'], str(deletion2))

if __name__ == '__main__':
    unittest.main()
