from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from typing import Any, cast

from accounts.jwt import issue_access_token
from accounts.models import User


class IngestEndpointCreateResponseTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_create_ingest_endpoint_returns_header_key_and_uuid_url(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        access = issue_access_token(user)
        resp = self.client.post(
            "/api/ingest-endpoints",
            data={"name": "ep"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {access}",
        )
        resp = cast(Any, resp)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertIn("endpoint", data)
        self.assertIn("ingest_key", data)
        self.assertIn("ingest_url", data)
        self.assertNotIn("token", data)

        endpoint_id = data["endpoint"]["id"]
        self.assertIn(
            f"/api/ingest/{str(endpoint_id).replace('-', '')}", data["ingest_url"]
        )
        self.assertNotIn(data["ingest_key"], data["ingest_url"])
