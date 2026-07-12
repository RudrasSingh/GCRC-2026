import os
import unittest

from fastapi.testclient import TestClient

from dashboard.api import app


class CryptoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.pop("user", None)
        os.environ.pop("password", None)
        os.environ.pop("host", None)
        cls.client = TestClient(app)

    def test_crypto_endpoints_require_session(self) -> None:
        # Keygen requires a session token
        response = self.client.post("/kem/keygen")
        self.assertEqual(response.status_code, 401)

    def _register_user(self, email: str, password: str = "very-secure-password") -> str:
        register_response = self.client.post(
            "/auth/register",
            json={
                "email": email,
                "password": password,
                "full_name": "Test User",
            },
        )
        self.assertEqual(register_response.status_code, 200)
        return register_response.json()["session_token"]

    def test_kem_keygen_encapsulate_decapsulate_roundtrip(self) -> None:
        session_token = self._register_user("dave@example.com")
        auth_headers = {"Authorization": f"Bearer {session_token}"}
        
        keygen_response = self.client.post("/kem/keygen", headers=auth_headers)
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()

        me_response = self.client.get("/auth/me", headers=auth_headers)
        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.json()["user"]["mlkem_public_key"], keygen_payload["public_key"])

        encapsulate_response = self.client.post(
            "/kem/encapsulate",
            headers=auth_headers,
            json={},
        )
        self.assertEqual(encapsulate_response.status_code, 200)
        encapsulate_payload = encapsulate_response.json()

        # Decapsulate using the ephemeral key handle
        decapsulate_response = self.client.post(
            "/kem/decapsulate",
            headers=auth_headers,
            json={
                "ciphertext": encapsulate_payload["ciphertext"],
                "secret_key_handle": keygen_payload["secret_key_handle"]
            },
        )
        self.assertEqual(decapsulate_response.status_code, 200)
        decapsulate_payload = decapsulate_response.json()

        self.assertEqual(
            encapsulate_payload["shared_secret_fingerprint"],
            decapsulate_payload["shared_secret_fingerprint"],
        )
        self.assertNotEqual(
            encapsulate_payload["shared_secret_handle"],
            decapsulate_payload["shared_secret_handle"],
        )

        # Decapsulate using None/managed-server-side handle -> should fail (400)
        decapsulate_response_fail = self.client.post(
            "/kem/decapsulate",
            headers=auth_headers,
            json={
                "ciphertext": encapsulate_payload["ciphertext"],
                "secret_key_handle": "managed-server-side"
            },
        )
        self.assertEqual(decapsulate_response_fail.status_code, 400)

    def test_crypto_encrypt_decrypt_roundtrip(self) -> None:
        session_token = self._register_user("eve@example.com")
        auth_headers = {"Authorization": f"Bearer {session_token}"}
        
        keygen_response = self.client.post("/kem/keygen", headers=auth_headers)
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()
        self.assertIn("secret_key", keygen_payload)
        self.assertIsNotNone(keygen_payload["secret_key"])

        encrypt_response = self.client.post(
            "/crypto/encrypt",
            headers=auth_headers,
            json={
                "message": "HELLO WORLD",
            },
        )
        self.assertEqual(encrypt_response.status_code, 200)
        encrypted_payload = encrypt_response.json()

        # Test decrypt with default (None) handle -> should fail (400)
        decrypt_response = self.client.post(
            "/crypto/decrypt",
            headers=auth_headers,
            json={
                "package": encrypted_payload,
            },
        )
        self.assertEqual(decrypt_response.status_code, 400)

        # Test decrypt with explicit 'managed-server-side' handle -> should fail (400)
        decrypt_response_managed = self.client.post(
            "/crypto/decrypt",
            headers=auth_headers,
            json={
                "package": encrypted_payload,
                "secret_key_handle": "managed-server-side",
            },
        )
        self.assertEqual(decrypt_response_managed.status_code, 400)

        # Test decrypt with ephemeral handle returned from keygen -> should succeed (200)
        decrypt_response_ephemeral = self.client.post(
            "/crypto/decrypt",
            headers=auth_headers,
            json={
                "package": encrypted_payload,
                "secret_key_handle": keygen_payload["secret_key_handle"],
            },
        )
        self.assertEqual(decrypt_response_ephemeral.status_code, 200)
        self.assertEqual(decrypt_response_ephemeral.json()["plaintext"], "HELLO WORLD")

        # Test decrypt with raw private key hex string -> should succeed (200)
        decrypt_response_hex = self.client.post(
            "/crypto/decrypt",
            headers=auth_headers,
            json={
                "package": encrypted_payload,
                "secret_key_handle": keygen_payload["secret_key"],
            },
        )
        self.assertEqual(decrypt_response_hex.status_code, 200)
        self.assertEqual(decrypt_response_hex.json()["plaintext"], "HELLO WORLD")

    def test_decapsulate_handle_resolution(self) -> None:
        session_token = self._register_user("frank@example.com")
        auth_headers = {"Authorization": f"Bearer {session_token}"}
        
        keygen_response = self.client.post("/kem/keygen", headers=auth_headers)
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()

        encapsulate_response = self.client.post(
            "/kem/encapsulate",
            headers=auth_headers,
            json={},
        )
        self.assertEqual(encapsulate_response.status_code, 200)
        encapsulate_payload = encapsulate_response.json()

        # Test decapsulate with ephemeral handle returned from keygen -> should succeed
        decapsulate_response_ephemeral = self.client.post(
            "/kem/decapsulate",
            headers=auth_headers,
            json={
                "ciphertext": encapsulate_payload["ciphertext"],
                "secret_key_handle": keygen_payload["secret_key_handle"],
            },
        )
        self.assertEqual(decapsulate_response_ephemeral.status_code, 200)
        self.assertEqual(
            encapsulate_payload["shared_secret_fingerprint"],
            decapsulate_response_ephemeral.json()["shared_secret_fingerprint"],
        )

        # Test decapsulate with raw private key hex string -> should succeed
        decapsulate_response_hex = self.client.post(
            "/kem/decapsulate",
            headers=auth_headers,
            json={
                "ciphertext": encapsulate_payload["ciphertext"],
                "secret_key_handle": keygen_payload["secret_key"],
            },
        )
        self.assertEqual(decapsulate_response_hex.status_code, 200)
        self.assertEqual(
            encapsulate_payload["shared_secret_fingerprint"],
            decapsulate_response_hex.json()["shared_secret_fingerprint"],
        )


if __name__ == "__main__":
    unittest.main()