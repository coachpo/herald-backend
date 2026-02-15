from rest_framework.permissions import BasePermission, SAFE_METHODS


class VerifiedEmailForUnsafeMethods(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        user = getattr(request, "user", None)
        return bool(getattr(user, "is_verified", False))
