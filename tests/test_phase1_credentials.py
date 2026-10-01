"""
Unit tests for Phase 1: Android Core Security, CredentialStore, and EndpointConfig.
"""

import unittest
from ashwin.core.endpoint_config import EndpointConfig
from ashwin.core.credentials import CredentialStore


class TestPhase1CredentialsAndConfig(unittest.TestCase):

    def test_endpoint_config_defaults_and_customization(self):
        # Default config
        cfg = EndpointConfig()
        self.assertEqual(cfg.host, "10.202.197.15")
        self.assertEqual(cfg.port, 8443)
        self.assertTrue(cfg.use_tls)
        self.assertEqual(cfg.base_url, "https://10.202.197.15:8443")
        self.assertTrue(cfg.is_configured())

        # Custom config
        custom_cfg = EndpointConfig(host="192.168.1.50", port=9443, use_tls=True)
        self.assertEqual(custom_cfg.base_url, "https://192.168.1.50:9443")

        # Invalid host/port
        with self.assertRaises(ValueError):
            EndpointConfig(host="")
        with self.assertRaises(ValueError):
            EndpointConfig(port=70000)

    def test_cloud_api_key_lifecycle(self):
        store = CredentialStore()
        self.assertFalse(store.has_cloud_api_key())
        self.assertIsNone(store.get_cloud_api_key())

        store.set_cloud_api_key("AIzaSyTestApiKey12345")
        self.assertTrue(store.has_cloud_api_key())
        self.assertEqual(store.get_cloud_api_key(), "AIzaSyTestApiKey12345")

        store.clear_cloud_api_key()
        self.assertFalse(store.has_cloud_api_key())
        self.assertIsNone(store.get_cloud_api_key())

    def test_moto_identity_and_pairing_revocation(self):
        store = CredentialStore()
        self.assertFalse(store.is_moto_paired())

        # Set transport PEMs
        store.set_moto_transport_identity(
            cert_pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            key_pem="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
        )
        self.assertIsNotNone(store.get_moto_transport_cert_pem())
        self.assertIsNotNone(store.get_moto_transport_key_pem())

        # Set app keys & pair
        app_priv = b"\x01" * 32
        app_pub = "abcdef123456"
        store.set_moto_application_identity(app_pub, app_priv)
        self.assertEqual(store.get_moto_app_public_key(), app_pub)
        self.assertEqual(store.get_moto_app_private_key(), app_priv)

        session_key = b"\x02" * 32
        server_pub = "fedcba654321"
        store.complete_moto_pairing(server_pub, session_key)
        self.assertTrue(store.is_moto_paired())
        self.assertEqual(store.get_moto_pinned_peer_public_key(), server_pub)
        self.assertEqual(store.get_moto_session_key(), session_key)

        # Revoke
        store.revoke_moto_pairing()
        self.assertFalse(store.is_moto_paired())
        self.assertIsNone(store.get_moto_pinned_peer_public_key())
        self.assertIsNone(store.get_moto_session_key())


if __name__ == "__main__":
    unittest.main()
