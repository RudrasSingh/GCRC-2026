import os
import unittest

from fastapi.testclient import TestClient

from dashboard.api import app


def _auth_headers() -> dict[str, str]:
    return {"X-API-Key": "test-api-key"}


class CryptoApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ["GCRC_API_KEY"] = "test-api-key"
        cls.client = TestClient(app)

    def test_crypto_endpoints_require_api_key(self) -> None:
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
        return register_response.json()["api_key"]

    def test_kem_keygen_encapsulate_decapsulate_roundtrip(self) -> None:
        api_key = self._register_user("dave@example.com")
        keygen_response = self.client.post("/kem/keygen", headers={"X-API-Key": api_key})
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()

        me_response = self.client.get("/auth/me", headers={"X-API-Key": api_key})
        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.json()["user"]["mlkem_public_key"], keygen_payload["public_key"])

        encapsulate_response = self.client.post(
            "/kem/encapsulate",
            headers={"X-API-Key": api_key},
            json={},
        )
        self.assertEqual(encapsulate_response.status_code, 200)
        encapsulate_payload = encapsulate_response.json()

        decapsulate_response = self.client.post(
            "/kem/decapsulate",
            headers={"X-API-Key": api_key},
            json={"ciphertext": encapsulate_payload["ciphertext"]},
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

    def test_crypto_encrypt_decrypt_roundtrip(self) -> None:
        api_key = self._register_user("eve@example.com")
        keygen_response = self.client.post("/kem/keygen", headers={"X-API-Key": api_key})
        self.assertEqual(keygen_response.status_code, 200)
        keygen_payload = keygen_response.json()

        encrypt_response = self.client.post(
            "/crypto/encrypt",
            headers={"X-API-Key": api_key},
            json={
                "message": "HELLO WORLD",
            },
        )
        self.assertEqual(encrypt_response.status_code, 200)
        encrypted_payload = encrypt_response.json()

        decrypt_response = self.client.post(
            "/crypto/decrypt",
            headers={"X-API-Key": api_key},
            json={
                "package": encrypted_payload,
            },
        )
        self.assertEqual(decrypt_response.status_code, 200)
        self.assertEqual(decrypt_response.json()["plaintext"], "HELLO WORLD")


if __name__ == "__main__":
    unittest.main()