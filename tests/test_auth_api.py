import os
import unittest

from fastapi.testclient import TestClient

from dashboard.api import app


class AuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.pop("user", None)
        os.environ.pop("password", None)
        os.environ.pop("host", None)
        cls.client = TestClient(app)

    def test_register_login_and_rotate_lifecycle(self) -> None:
        # Register a new user (with relaxed password constraint hello@123)
        register_response = self.client.post(
            "/auth/register",
            json={
                "email": "alice@example.com",
                "password": "hello@123",
                "full_name": "Alice Example",
            },
        )
        self.assertEqual(register_response.status_code, 200)
        register_payload = register_response.json()
        original_public_key = register_payload["mlkem_public_key"]
        
        # Zero-knowledge check: Private key must be returned on registration
        self.assertIsNotNone(register_payload["mlkem_private_key"])

        # Login
        login_response = self.client.post(
            "/auth/login",
            json={
                "email": "alice@example.com",
                "password": "hello@123",
            },
        )
        self.assertEqual(login_response.status_code, 200)
        login_payload = login_response.json()
        self.assertEqual(login_payload["email"], "alice@example.com")
        self.assertEqual(login_payload["mlkem_public_key"], original_public_key)
        
        # Zero-knowledge check: Private key must NOT be returned on login
        self.assertIsNone(login_payload["mlkem_private_key"])

        # Rotate ML-KEM keys
        rotate_response = self.client.post(
            "/auth/mlkem-keys/rotate",
            json={
                "email": "alice@example.com",
                "password": "hello@123",
            },
        )
        self.assertEqual(rotate_response.status_code, 200)
        rotate_payload = rotate_response.json()
        self.assertNotEqual(rotate_payload["mlkem_public_key"], original_public_key)
        
        # Zero-knowledge check: Private key must be returned on rotation
        self.assertIsNotNone(rotate_payload["mlkem_private_key"])

    def test_invalid_login(self) -> None:
        login_response = self.client.post(
            "/auth/login",
            json={
                "email": "alice@example.com",
                "password": "wrong-password",
            },
        )
        self.assertEqual(login_response.status_code, 401)


if __name__ == "__main__":
    unittest.main()