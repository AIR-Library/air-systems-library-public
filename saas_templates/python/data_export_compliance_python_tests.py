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
    DeletionRequestStatus
)

class TestComplianceManager(unittest.TestCase):
    def setUp(self):
        # Create in-memory SQLite database
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
        
        # Initialize compliance manager
        self.compliance = ComplianceManager(
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
    
    def test_export_csv_format(self):
        result = self.compliance.request_data_export(self.test_user_id, 'csv')
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'pending')
        export_id = uuid.UUID(result['export_id'])
        
        export_request = self.db_session.query(ExportRequest).filter_by(id=export_id).first()
        self.assertEqual(export_request.format, 'csv')
    
    def test_export_invalid_format(self):
        with self.assertRaises(ValueError):
            self.compliance.request_data_export(self.test_user_id, 'xml')
    
    def test_export_processing(self):
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
    
    def test_request_deletion(self):
        reason = 'gdpr_request'
        result = self.compliance.request_account_deletion(self.test_user_id, reason)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['status'], 'pending')
        self.assertIn('deletion_id', result)
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
        
        # Check email sent
        self.email_service.assert_called()
        args, kwargs = self.email_service.call_args
        self.assertEqual(args[0], 'test@example.com')
        self.assertIn('Confirm account deletion', args[1])
        self.assertIn(str(deletion_id), args[2])
        self.assertIn(deletion_request.confirmation_token, args[2])
    
    def test_request_deletion_invalid_reason(self):
        with self.assertRaises(ValueError):
            self.compliance.request_account_deletion(self.test_user_id, 'invalid_reason')
    
    def test_confirm_deletion_success(self):
        # Create deletion request
        deletion_id = uuid.uuid4()
        confirmation_token = 'valid_token'
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.PENDING,
            reason='gdpr_request',
            confirmation_token=confirmation_token,
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        # Confirm deletion
        result = self.compliance.confirm_deletion(deletion_id, confirmation_token)
        
        self.assertTrue(result['success'])
        self.assertIn('deletion_scheduled_for', result)
        
        # Check deletion request updated
        deletion_request = self.db_session.query(DeletionRequest).filter_by(id=deletion_id).first()
        self.assertEqual(deletion_request.status, DeletionRequestStatus.APPROVED)
        
        # Check audit log
        self.audit_logger.assert_called_with(
            action='deletion_confirmed',
            user_id=self.test_user_id,
            details={'deletion_id': str(deletion_id)}
        )
    
    def test_confirm_deletion_invalid_token(self):
        deletion_id = uuid.uuid4()
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.PENDING,
            reason='gdpr_request',
            confirmation_token='valid_token',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        with self.assertRaises(ValueError):
            self.compliance.confirm_deletion(deletion_id, 'invalid_token')
    
    def test_confirm_deletion_wrong_status(self):
        deletion_id = uuid.uuid4()
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.APPROVED,  # Already approved
            reason='gdpr_request',
            confirmation_token='token',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        with self.assertRaises(ValueError):
            self.compliance.confirm_deletion(deletion_id, 'token')
    
    def test_cancel_deletion_within_grace_period(self):
        deletion_id = uuid.uuid4()
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.PENDING,
            reason='gdpr_request',
            confirmation_token='token',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        # Cancel deletion
        result = self.compliance.cancel_deletion(deletion_id)
        
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
    
    def test_cancel_deletion_after_grace_period(self):
        deletion_id = uuid.uuid4()
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc) - timedelta(days=31),
            status=DeletionRequestStatus.PENDING,
            reason='gdpr_request',
            confirmation_token='token',
            will_delete_at=datetime.now(timezone.utc) - timedelta(days=1)  # Expired
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        with self.assertRaises(ValueError):
            self.compliance.cancel_deletion(deletion_id)
    
    def test_cancel_deletion_wrong_status(self):
        deletion_id = uuid.uuid4()
        deletion_request = DeletionRequest(
            id=deletion_id,
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.COMPLETED,  # Already completed
            reason='gdpr_request',
            confirmation_token='token',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        self.db_session.add(deletion_request)
        self.db_session.commit()
        
        with self.assertRaises(ValueError):
            self.compliance.cancel_deletion(deletion_id)
    
    def test_list_export_requests(self):
        # Create test exports
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
        
        # List all exports for test user
        result = self.compliance.list_export_requests(admin_user_id=uuid.uuid4(), user_id=self.test_user_id)
        
        self.assertEqual(result['total'], 2)
        export_ids = [str(e['export_id']) for e in result['exports']]
        self.assertIn(str(export1.id), export_ids)
        self.assertIn(str(export2.id), export_ids)
        self.assertNotIn(str(export3.id), export_ids)
        
        # List completed exports
        result = self.compliance.list_export_requests(admin_user_id=uuid.uuid4(), status=ExportRequestStatus.COMPLETED)
        self.assertEqual(result['total'], 2)  # export1 and export3
        
        # List pending exports for test user
        result = self.compliance.list_export_requests(admin_user_id=uuid.uuid4(), user_id=self.test_user_id, status=ExportRequestStatus.PENDING)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['exports'][0]['export_id'], str(export2.id))
    
    def test_list_deletion_requests(self):
        # Create test deletions
        deletion1 = DeletionRequest(
            id=uuid.uuid4(),
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.PENDING,
            reason='gdpr_request',
            confirmation_token='token1',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        deletion2 = DeletionRequest(
            id=uuid.uuid4(),
            user_id=self.test_user_id,
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.APPROVED,
            reason='user_requested',
            confirmation_token='token2',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        deletion3 = DeletionRequest(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),  # Different user
            requested_at=datetime.now(timezone.utc),
            status=DeletionRequestStatus.PENDING,
            reason='other',
            confirmation_token='token3',
            will_delete_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        self.db_session.add_all([deletion1, deletion2, deletion3])
        self.db_session.commit()
        
        # List all deletions for test user
        result = self.compliance.list_deletion_requests(admin_user_id=uuid.uuid4())
        
        self.assertEqual(result['total'], 3)
        deletion_ids = [str(d['deletion_id']) for d in result['deletions']]
        self.assertIn(str(deletion1.id), deletion_ids)
        self.assertIn(str(deletion2.id), deletion_ids)
        self.assertIn(str(deletion3.id), deletion_ids)
        
        # List pending deletions
        result = self.compliance.list_deletion_requests(admin_user_id=uuid.uuid4(), status=DeletionRequestStatus.PENDING)
        self.assertEqual(result['total'], 2)  # deletion1 and deletion3
        
        # List approved deletions
        result = self.compliance.list_deletion_requests(admin_user_id=uuid.uuid4(), status=DeletionRequestStatus.APPROVED)
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['deletions'][0]['deletion_id'], str(deletion2.id))

if __name__ == '__main__':
    unittest.main()
