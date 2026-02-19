from django.urls import path, register_converter

from .ingest import ingest_view
from .converters import UUIDHexConverter
from .views_auth import (
    ChangeEmailView,
    ChangePasswordView,
    DeleteAccountView,
    ForgotPasswordView,
    LoginView,
    LogoutView,
    MeView,
    RefreshView,
    ResendVerificationView,
    ResetPasswordView,
    SignupView,
    VerifyEmailView,
)
from .views_resources import (
    ChannelDetailView,
    ChannelTestView,
    ChannelsView,
    IngestEndpointArchiveView,
    IngestEndpointRevokeView,
    IngestEndpointsView,
    MessageDeliveriesView,
    MessageDetailView,
    MessagesBatchDeleteView,
    MessagesView,
    RuleDetailView,
    RulesView,
    RulesTestView,
    RuleTestView,
)


register_converter(UUIDHexConverter, "uuidhex")


urlpatterns = [
    path("auth/signup", SignupView.as_view()),
    path("auth/login", LoginView.as_view()),
    path("auth/refresh", RefreshView.as_view()),
    path("auth/logout", LogoutView.as_view()),
    path("auth/me", MeView.as_view()),
    path("auth/resend-verification", ResendVerificationView.as_view()),
    path("auth/verify-email", VerifyEmailView.as_view()),
    path("auth/forgot-password", ForgotPasswordView.as_view()),
    path("auth/reset-password", ResetPasswordView.as_view()),
    path("auth/change-email", ChangeEmailView.as_view()),
    path("auth/change-password", ChangePasswordView.as_view()),
    path("auth/delete-account", DeleteAccountView.as_view()),
    path("ingest/<uuid:endpoint_id>", ingest_view),
    path("ingest/<uuidhex:endpoint_id>", ingest_view),
    path("ingest-endpoints", IngestEndpointsView.as_view()),
    path("ingest-endpoints/<uuid:id>/revoke", IngestEndpointRevokeView.as_view()),
    path("ingest-endpoints/<uuid:id>", IngestEndpointArchiveView.as_view()),
    path("messages", MessagesView.as_view()),
    path("messages/batch-delete", MessagesBatchDeleteView.as_view()),
    path("messages/<uuid:id>", MessageDetailView.as_view()),
    path("channels", ChannelsView.as_view()),
    path("channels/<uuid:id>", ChannelDetailView.as_view()),
    path("channels/<uuid:id>/test", ChannelTestView.as_view()),
    path("rules", RulesView.as_view()),
    path("rules/test", RulesTestView.as_view()),
    path("rules/<uuid:id>", RuleDetailView.as_view()),
    path("rules/<uuid:id>/test", RuleTestView.as_view()),
    path("messages/<uuid:id>/deliveries", MessageDeliveriesView.as_view()),
]
