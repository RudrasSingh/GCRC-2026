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

    def test_kem_keygen_encapsulate_decapsulate_roundtrip(self) -> None:
        # Generate KEM keys
        keygen_response = self.client.post("/kem/keygen")
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()
        public_key = keygen_payload["public_key"]
        secret_key = keygen_payload["secret_key"]

        # Encapsulate
        encapsulate_response = self.client.post(
            "/kem/encapsulate",
            json={"public_key": public_key},
        )
        self.assertEqual(encapsulate_response.status_code, 200)
        encapsulate_payload = encapsulate_response.json()

        # Decapsulate
        decapsulate_response = self.client.post(
            "/kem/decapsulate",
            json={
                "ciphertext": encapsulate_payload["ciphertext"],
                "secret_key": secret_key
            },
        )
        self.assertEqual(decapsulate_response.status_code, 200)
        decapsulate_payload = decapsulate_response.json()

        # Check fingers match
        self.assertEqual(
            encapsulate_payload["shared_secret_fingerprint"],
            decapsulate_payload["shared_secret_fingerprint"],
        )
        self.assertEqual(
            encapsulate_payload["shared_secret"],
            decapsulate_payload["shared_secret"],
        )

    def test_crypto_encrypt_decrypt_roundtrip(self) -> None:
        # Keygen
        keygen_response = self.client.post("/kem/keygen")
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()
        public_key = keygen_payload["public_key"]
        secret_key = keygen_payload["secret_key"]

        # Encrypt message
        encrypt_response = self.client.post(
            "/crypto/encrypt",
            json={
                "message": "HELLO WORLD SECURITY",
                "public_key": public_key
            },
        )
        self.assertEqual(encrypt_response.status_code, 200)
        encrypted_payload = encrypt_response.json()

        # Decrypt message
        decrypt_response = self.client.post(
            "/crypto/decrypt",
            json={
                "package": encrypted_payload,
                "secret_key": secret_key
            },
        )
        self.assertEqual(decrypt_response.status_code, 200)
        self.assertEqual(decrypt_response.json()["plaintext"], "HELLO WORLD SECURITY")

    def test_crypto_encrypt_with_email_fallback(self) -> None:
        # Register user
        register_response = self.client.post(
            "/auth/register",
            json={
                "email": "bob@example.com",
                "password": "hello@123",
                "full_name": "Bob Example",
            },
        )
        self.assertEqual(register_response.status_code, 200)
        register_payload = register_response.json()
        private_key = register_payload["mlkem_private_key"]

        # Encrypt utilizing email fallback
        encrypt_response = self.client.post(
            "/crypto/encrypt",
            json={
                "message": "SECRET EMAIL FALLBACK",
                "email": "bob@example.com"
            },
        )
        self.assertEqual(encrypt_response.status_code, 200)
        encrypted_payload = encrypt_response.json()

        # Decrypt with raw private key
        decrypt_response = self.client.post(
            "/crypto/decrypt",
            json={
                "package": encrypted_payload,
                "secret_key": private_key
            },
        )
        self.assertEqual(decrypt_response.status_code, 200)
        self.assertEqual(decrypt_response.json()["plaintext"], "SECRET EMAIL FALLBACK")


if __name__ == "__main__":
    unittest.main()