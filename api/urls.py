from django.urls import path

from .ingest import ingest_view
from .views_auth import (
    ChangeEmailView,
    ChangePasswordView,
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
    ChannelsView,
    IngestEndpointRevokeView,
    IngestEndpointsView,
    MessageDeliveriesView,
    MessageDetailView,
    MessagesBatchDeleteView,
    MessagesView,
    RuleDetailView,
    RulesView,
    RuleTestView,
)


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
    path("ingest/<str:token>", ingest_view),
    path("ingest-endpoints", IngestEndpointsView.as_view()),
    path("ingest-endpoints/<uuid:id>/revoke", IngestEndpointRevokeView.as_view()),
    path("messages", MessagesView.as_view()),
    path("messages/batch-delete", MessagesBatchDeleteView.as_view()),
    path("messages/<uuid:id>", MessageDetailView.as_view()),
    path("channels", ChannelsView.as_view()),
    path("channels/<uuid:id>", ChannelDetailView.as_view()),
    path("rules", RulesView.as_view()),
    path("rules/<uuid:id>", RuleDetailView.as_view()),
    path("rules/<uuid:id>/test", RuleTestView.as_view()),
    path("messages/<uuid:id>/deliveries", MessageDeliveriesView.as_view()),
]
