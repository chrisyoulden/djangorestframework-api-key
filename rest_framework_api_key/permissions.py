from django.conf import settings
from rest_framework import permissions

from .models import APIKey


class KeyParser:
    def get(self, request):
        custom_header = getattr(settings, "API_KEY_CUSTOM_HEADER", None)

        if custom_header is not None:
            return self.get_from_header(request, custom_header)

        return self.get_from_authorization(request)

    def get_from_authorization(self, request):
        authorization = request.META.get("HTTP_AUTHORIZATION")

        if not authorization:
            return None

        try:
            _, key = authorization.split("Api-Key ")
        except ValueError:
            key = None

        return key

    def get_from_header(self, request, name):
        return request.META.get(name) or None


class BaseHasAPIKey(permissions.BasePermission):
    model = None  # type: typing.Type[models.Model]
    key_parser = KeyParser()

    def get_key(self, request):
        return self.key_parser.get(request)

    def has_permission(self, request, view):
        assert self.model is not None, (
            "%s must define `.model` with the API key model to use"
            % self.__class__.__name__
        )
        key = self.get_key(request)
        if not key:
            return False
        return self.model.objects.is_valid(key)

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class HasAPIKey(BaseHasAPIKey):
    model = APIKey
