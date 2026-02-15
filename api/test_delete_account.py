from django.conf import settings
from django.test import TestCase
from rest_framework.test import APIClient
from unittest.mock import patch

from accounts.jwt import issue_access_token
from accounts.models import User
from accounts.tokens import hash_token
from beacon.models import IngestEndpoint, Message


class DeleteAccountTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_delete_account_deletes_user_and_owned_data(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        access = issue_access_token(user)

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )
        Message.objects.create(
            user=user,
            ingest_endpoint=ep,
            content_type="text/plain",
            payload_text="hello",
            payload_sha256="",
            headers_json={},
            query_json={},
            remote_ip="127.0.0.1",
            user_agent="",
        )

        with patch("accounts.emails.send_mail"):
            resp = self.client.post(
                "/api/auth/delete-account",
                data={"password": "password123", "confirm": "DELETE"},
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {access}",
            )

        self.assertEqual(resp.status_code, 204)
        self.assertFalse(User.objects.filter(id=user.id).exists())
        self.assertEqual(IngestEndpoint.objects.count(), 0)
        self.assertEqual(Message.objects.count(), 0)

        self.assertIn(settings.JWT_REFRESH_COOKIE_NAME, resp.cookies)

    def test_delete_account_rejects_wrong_password(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        access = issue_access_token(user)

        with patch("accounts.emails.send_mail"):
            resp = self.client.post(
                "/api/auth/delete-account",
                data={"password": "wrong", "confirm": "DELETE"},
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {access}",
            )
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(User.objects.filter(id=user.id).exists())

    def test_delete_account_rejects_bad_confirm(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        access = issue_access_token(user)

        with patch("accounts.emails.send_mail"):
            resp = self.client.post(
                "/api/auth/delete-account",
                data={"password": "password123", "confirm": "nope"},
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {access}",
            )
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(User.objects.filter(id=user.id).exists())

    def test_delete_account_does_not_500_when_email_send_fails(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        access = issue_access_token(user)

        with patch("accounts.emails.send_mail", side_effect=Exception("smtp")):
            resp = self.client.post(
                "/api/auth/delete-account",
                data={"password": "password123", "confirm": "DELETE"},
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {access}",
            )
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(User.objects.filter(id=user.id).exists())
