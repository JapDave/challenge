from rest_framework_simplejwt.authentication import  JWTAuthentication
from django.conf import settings
from rest_framework import authentication, exceptions as rest_exceptions
from django.contrib.auth import get_user_model
from django.middleware.csrf import CsrfViewMiddleware
from ninja.security import HttpBearer

def enforce_csrf(request):
    check = authentication.CSRFCheck(request)
    reason = check.process_view(request, None, (), {})
    if reason:
      raise rest_exceptions.PermissionDenied('CSRF Failed: %s' % reason)


class CustomAuthentication(JWTAuthentication, HttpBearer):
    def authenticate(self, request, token):
        validated_token = self.get_validated_token(token)
        enforce_csrf(request)
        return self.get_user(validated_token)

