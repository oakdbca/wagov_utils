"""
Settings-level security checks.

Verifies that critical Django settings are configured securely.
"""

from django.conf import settings

from ..base import BaseSecurityCheck
from ..registry import SecurityCheckRegistry


@SecurityCheckRegistry.register
class ShowApiRootCheck(BaseSecurityCheck):
    check_id = "wagov_security.S001"
    title = "API root view should be hidden"
    description = (
        "SHOW_API_ROOT (or INCLUDE_ROOT_VIEW) should be False in production. "
        "Exposing the API root view reveals the full list of available endpoints."
    )
    category = "settings"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        # Support both naming conventions
        show_api_root = getattr(settings, "SHOW_API_ROOT", None)
        include_root_view = getattr(settings, "INCLUDE_ROOT_VIEW", None)

        value = show_api_root if show_api_root is not None else include_root_view

        if value is True and not getattr(settings, "DEBUG", False):
            return [
                self.make_warning(
                    "API root view is enabled in a non-DEBUG environment. "
                    "Set SHOW_API_ROOT=False (or INCLUDE_ROOT_VIEW=False).",
                    hint=(
                        "Add SHOW_API_ROOT = env('SHOW_API_ROOT', False) to settings.py "
                        "and router.include_root_view = settings.SHOW_API_ROOT to urls.py."
                    ),
                )
            ]

        if value is None:
            return [
                self.make_info(
                    "Neither SHOW_API_ROOT nor INCLUDE_ROOT_VIEW is explicitly set in settings. "
                    "It is recommended to set one of these to False explicitly.",
                    hint="Add SHOW_API_ROOT = env('SHOW_API_ROOT', False) to settings.py.",
                    severity="info",
                )
            ]

        return []


@SecurityCheckRegistry.register
class SessionCookieSecureCheck(BaseSecurityCheck):
    check_id = "wagov_security.S002"
    title = "SESSION_COOKIE_SECURE should be True"
    description = "The session cookie must be marked Secure so it is only transmitted over HTTPS connections."
    category = "settings"
    severity = "error"

    def run(self, app_configs=None, **kwargs):
        value = getattr(settings, "SESSION_COOKIE_SECURE", False)
        if not value and not getattr(settings, "DEBUG", False):
            return [
                self.make_error(
                    "SESSION_COOKIE_SECURE is not True. Session cookies will be "
                    "transmitted over insecure HTTP connections.",
                    hint="Add SESSION_COOKIE_SECURE = env('SESSION_COOKIE_SECURE', True) to settings.py.",
                )
            ]
        return []


@SecurityCheckRegistry.register
class CsrfCookieSecureCheck(BaseSecurityCheck):
    check_id = "wagov_security.S003"
    title = "CSRF_COOKIE_SECURE should be True"
    description = "The CSRF cookie must be marked Secure so it is only transmitted over HTTPS connections."
    category = "settings"
    severity = "error"

    def run(self, app_configs=None, **kwargs):
        value = getattr(settings, "CSRF_COOKIE_SECURE", False)
        if not value and not getattr(settings, "DEBUG", False):
            return [
                self.make_error(
                    "CSRF_COOKIE_SECURE is not True. CSRF cookies will be transmitted over insecure HTTP connections.",
                    hint="Add CSRF_COOKIE_SECURE = env('CSRF_COOKIE_SECURE', True) to settings.py.",
                )
            ]
        return []


@SecurityCheckRegistry.register
class PrivateMediaLocationCheck(BaseSecurityCheck):
    check_id = "wagov_security.S004"
    title = "PRIVATE_MEDIA_STORAGE_LOCATION should be configured"
    description = (
        "A dedicated private media storage location should be configured so "
        "that sensitive uploaded/generated files are not publicly accessible."
    )
    category = "settings"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        has_private_media = any(
            hasattr(settings, attr)
            for attr in (
                "PRIVATE_MEDIA_STORAGE_LOCATION",
                "PRIVATE_MEDIA_ROOT",
                "PRIVATE_MEDIA_BASE_URL",
            )
        )
        if not has_private_media:
            return [
                self.make_warning(
                    "No PRIVATE_MEDIA_STORAGE_LOCATION (or equivalent) setting found. "
                    "Sensitive files may be served publicly.",
                    hint=(
                        "Define PRIVATE_MEDIA_STORAGE_LOCATION and PRIVATE_MEDIA_BASE_URL "
                        "in settings.py and use django.core.files.storage.FileSystemStorage "
                        "with those values for sensitive FileFields."
                    ),
                )
            ]
        return []


@SecurityCheckRegistry.register
class DataUploadMaxFieldsCheck(BaseSecurityCheck):
    check_id = "wagov_security.S005"
    title = "DATA_UPLOAD_MAX_NUMBER_FIELDS should be set"
    description = (
        "Django's DATA_UPLOAD_MAX_NUMBER_FIELDS limits how many form fields "
        "a single request can submit. Setting it to None removes the limit, "
        "which could be a DoS vector."
    )
    category = "settings"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        value = getattr(settings, "DATA_UPLOAD_MAX_NUMBER_FIELDS", 1000)
        if value is None:
            return [
                self.make_warning(
                    "DATA_UPLOAD_MAX_NUMBER_FIELDS is set to None (unlimited). "
                    "This removes the limit on the number of form fields per request "
                    "and could be exploited for denial-of-service attacks.",
                    hint=(
                        "Set DATA_UPLOAD_MAX_NUMBER_FIELDS to a reasonable value "
                        "(Django default is 1000) unless unlimited fields are specifically required."
                    ),
                )
            ]
        return []
