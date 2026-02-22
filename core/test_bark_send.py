from unittest.mock import Mock, patch

from django.test import TestCase

from core.bark import send_bark_push


class BarkSendFallbackTests(TestCase):
    @patch("core.bark.assert_ssrf_safe")
    @patch("core.bark.requests.get")
    @patch("core.bark.requests.post")
    def test_falls_back_to_legacy_get_on_404(
        self, post: Mock, get: Mock, assert_ssrf_safe: Mock
    ):
        post.return_value = Mock(
            status_code=404,
            headers={"Content-Type": "text/plain"},
            content=b"not found",
        )
        get.return_value = Mock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b'{"code":200,"message":"success"}',
            json=lambda: {"code": 200, "message": "success"},
        )

        ok, meta = send_bark_push(
            server_base_url="https://bark.example.com",
            payload={
                "device_key": "Abcdef0123456789",
                "title": "Smoke",
                "body": "Hello",
            },
        )
        self.assertTrue(ok)
        self.assertEqual(meta.get("fallback"), "legacy_get")
        self.assertTrue(get.called)
