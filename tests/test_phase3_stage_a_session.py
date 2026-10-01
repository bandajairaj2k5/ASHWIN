"""
Unit tests for Phase 3 / Stage A: Core Security & Session Foundation.
"""

import unittest
from ashwin.core.session import CoreSession, CoreSessionError
from ashwin.core.credentials import CredentialStore
from ashwin.core.secret_scanner import SecretScanner
from ashwin.core.audit import AuditLogger


class TestPhase3StageASession(unittest.TestCase):

    def setUp(self):
        self.credential_store = CredentialStore()
        self.scanner = SecretScanner()
        self.audit_logger = AuditLogger()

    def test_session_initialization_and_health(self):
        session = CoreSession(
            credential_store=self.credential_store,
            scanner=self.scanner,
            audit_logger=self.audit_logger
        )

        self.assertTrue(session.is_active)
        self.assertTrue(session.is_healthy())
        self.assertIsNotNone(session.session_id)
        self.assertGreater(len(session.session_id), 10)
        self.assertGreater(session.created_at, 0)

        # Verify audit event
        events = self.audit_logger.get_entries()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "SESSION_START")
        self.assertEqual(events[0].details["session_id"], session.session_id)

    def test_unhealthy_scanner_fails_session_initialization(self):
        unhealthy_scanner = SecretScanner(healthy=False)

        with self.assertRaises(CoreSessionError) as cm:
            CoreSession(
                credential_store=self.credential_store,
                scanner=unhealthy_scanner,
                audit_logger=self.audit_logger
            )
        self.assertIn("SecretScanner is unhealthy", str(cm.exception))

    def test_session_reset_generates_new_id_preserves_credentials(self):
        session = CoreSession(
            credential_store=self.credential_store,
            scanner=self.scanner,
            audit_logger=self.audit_logger
        )
        old_id = session.session_id

        # Set credential in store
        self.credential_store.set_cloud_api_key("test_api_key_12345")

        # Reset session
        session.reset_session()
        self.assertNotEqual(session.session_id, old_id)
        self.assertTrue(session.is_active)
        self.assertTrue(session.is_healthy())

        # Verify credential is intact
        self.assertEqual(self.credential_store.get_cloud_api_key(), "test_api_key_12345")

        # Verify audit log recorded reset
        events = self.audit_logger.get_entries()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].event_type, "SESSION_RESET")
        self.assertEqual(events[1].details["previous_session_id"], old_id)
        self.assertEqual(events[1].details["new_session_id"], session.session_id)

    def test_session_termination(self):
        session = CoreSession(
            credential_store=self.credential_store,
            scanner=self.scanner,
            audit_logger=self.audit_logger
        )
        self.assertTrue(session.is_active)

        session.terminate_session()
        self.assertFalse(session.is_active)
        self.assertFalse(session.is_healthy())

        events = self.audit_logger.get_entries()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].event_type, "SESSION_TERMINATED")


if __name__ == "__main__":
    unittest.main()
