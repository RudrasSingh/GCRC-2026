import os
import unittest

from fastapi.testclient import TestClient

from dashboard.api import app


class AuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.pop("SUPABASE_URL", None)
        os.environ.pop("SUPABASE_SERVICE_ROLE_KEY", None)
        cls.client = TestClient(app)

    def test_register_login_and_api_key_lifecycle(self) -> None:
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
        self.assertIn("api_key", register_payload)
        original_public_key = register_payload["user"]["mlkem_public_key"]

        auth_headers = {"X-API-Key": register_payload["api_key"]}
        me_response = self.client.get("/auth/me", headers=auth_headers)
        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(me_response.json()["user"]["email"], "alice@example.com")
        self.assertEqual(me_response.json()["user"]["mlkem_public_key"], original_public_key)

        rotate_response = self.client.post("/auth/api-keys", headers=auth_headers, json={"label": "rotated"})
        self.assertEqual(rotate_response.status_code, 200)
        rotated_payload = rotate_response.json()
        self.assertIn("api_key", rotated_payload)
        self.assertNotEqual(rotated_payload["api_key"], register_payload["api_key"])

        old_key_response = self.client.get("/auth/me", headers=auth_headers)
        self.assertEqual(old_key_response.status_code, 200)

        list_response = self.client.get("/auth/api-keys", headers={"X-API-Key": rotated_payload["api_key"]})
        self.assertEqual(list_response.status_code, 200)
        self.assertGreaterEqual(len(list_response.json()), 2)

        revoke_response = self.client.delete(
            f"/auth/api-keys/{rotated_payload['api_key_id']}",
            headers={"X-API-Key": rotated_payload["api_key"]},
        )
        self.assertEqual(revoke_response.status_code, 200)

        rotate_keys_response = self.client.post("/auth/mlkem-keys/rotate", headers=auth_headers, json={"confirm": True})
        self.assertEqual(rotate_keys_response.status_code, 200)
        self.assertNotEqual(rotate_keys_response.json()["mlkem_public_key"], original_public_key)

    def test_login_returns_existing_key(self) -> None:
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
        self.assertIn("api_key", login_response.json())
        self.assertIn("mlkem_public_key", login_response.json()["user"])

    def test_crypto_routes_use_issue_api_key(self) -> None:
        register_response = self.client.post(
            "/auth/register",
            json={
                "email": "carol@example.com",
                "password": "another-very-secure-password",
                "full_name": "Carol Example",
            },
        )
        self.assertEqual(register_response.status_code, 200)
        api_key = register_response.json()["api_key"]

        keygen_response = self.client.post("/kem/keygen", headers={"X-API-Key": api_key})
        self.assertEqual(keygen_response.status_code, 200)


if __name__ == "__main__":
    unittest.main()