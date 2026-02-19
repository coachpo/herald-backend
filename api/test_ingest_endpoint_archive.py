from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.jwt import issue_access_token
from accounts.models import User
from accounts.tokens import hash_token
from beacon.models import IngestEndpoint, Message


class IngestEndpointArchiveTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_archive_hides_endpoint_and_blocks_ingest(self):
        user = User.objects.create_user(email="a@example.com", password="password123")
        user.email_verified_at = timezone.now()
        user.save(update_fields=["email_verified_at"])

        raw = "test-token"
        ep = IngestEndpoint.objects.create(
            user=user, name="ep", token_hash=hash_token(raw)
        )

        resp1 = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b'{"body":"hello"}',
            content_type="application/json",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(Message.objects.count(), 1)

        access = issue_access_token(user)
        resp2 = self.client.delete(
            f"/api/ingest-endpoints/{ep.id}",
            HTTP_AUTHORIZATION=f"Bearer {access}",
        )
        self.assertEqual(resp2.status_code, 204)

        ep.refresh_from_db()
        self.assertIsNotNone(ep.revoked_at)
        self.assertIsNotNone(ep.deleted_at)

        resp3 = self.client.get(
            "/api/ingest-endpoints",
            HTTP_AUTHORIZATION=f"Bearer {access}",
        )
        self.assertEqual(resp3.status_code, 200)
        ids = [x["id"] for x in resp3.json().get("endpoints", [])]
        self.assertNotIn(str(ep.id), ids)

        resp4 = self.client.post(
            f"/api/ingest/{ep.id.hex}",
            data=b'{"body":"hello2"}',
            content_type="application/json",
            HTTP_X_BEACON_INGEST_KEY=raw,
        )
        self.assertEqual(resp4.status_code, 401)
