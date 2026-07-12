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

    def test_register_login_and_logout_lifecycle(self) -> None:
        # Register a new user
        register_response = self.client.post(
            "/auth/register",
            json={
                "email": "alice@example.com",
                "password": "very-secure-password",
                "full_name": "Alice Example",
            },
        )
        self.assertEqual(register_response.status_code, 200)
        register_payload = register_response.json()
        self.assertIn("session_token", register_payload)
        session_token = register_payload["session_token"]
        original_public_key = register_payload["user"]["mlkem_public_key"]
        
        # Zero-knowledge check: Private key must be returned on registration
        self.assertIsNotNone(register_payload["user"]["mlkem_private_key"])

        # Call /auth/me with Bearer Auth
        auth_headers = {"Authorization": f"Bearer {session_token}"}
        me_response = self.client.get("/auth/me", headers=auth_headers)
        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.json()["user"]["email"], "alice@example.com")
        self.assertEqual(me_response.json()["user"]["mlkem_public_key"], original_public_key)
        
        # Zero-knowledge check: Private key must NOT be available on profile fetch
        self.assertIsNone(me_response.json()["user"]["mlkem_private_key"])

        # Login again
        login_response = self.client.post(
            "/auth/login",
            json={
                "email": "alice@example.com",
                "password": "very-secure-password",
            },
        )
        self.assertEqual(login_response.status_code, 200)
        login_payload = login_response.json()
        self.assertIn("session_token", login_payload)
        new_session_token = login_payload["session_token"]
        
        # Zero-knowledge check: Private key must NOT be returned on login
        self.assertIsNone(login_payload["user"]["mlkem_private_key"])

        # Rotate ML-KEM keys
        rotate_response = self.client.post(
            "/auth/mlkem-keys/rotate",
            headers={"Authorization": f"Bearer {new_session_token}"},
            json={"confirm": True},
        )
        self.assertEqual(rotate_response.status_code, 200)
        self.assertNotEqual(rotate_response.json()["mlkem_public_key"], original_public_key)
        
        # Zero-knowledge check: Private key must be returned on rotation
        self.assertIsNotNone(rotate_response.json()["mlkem_private_key"])

        # Logout of the second session
        logout_response = self.client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {new_session_token}"},
        )
        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(logout_response.json()["status"], "logged out")

        # Try to use the logged out session token -> should be Unauthorized (401)
        me_fail_response = self.client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {new_session_token}"},
        )
        self.assertEqual(me_fail_response.status_code, 401)

    def test_login_validation(self) -> None:
        self.client.post(
            "/auth/register",
            json={
                "email": "bob@example.com",
                "password": "another-secure-password",
                "full_name": "Bob Example",
            },
        )

        login_response = self.client.post(
            "/auth/login",
            json={
                "email": "bob@example.com",
                "password": "another-secure-password",
            },
        )
        self.assertEqual(login_response.status_code, 200)
        self.assertIn("session_token", login_response.json())
        self.assertIn("mlkem_public_key", login_response.json()["user"])
        # Zero-knowledge check: Private key is not stored or returned on login
        self.assertIsNone(login_response.json()["user"]["mlkem_private_key"])


if __name__ == "__main__":
    unittest.main()