"""
Django REST Framework configuration checks.

Ensures DRF is configured with safe defaults.
"""

from django.conf import settings

from ..base import BaseSecurityCheck
from ..registry import SecurityCheckRegistry


@SecurityCheckRegistry.register
class DefaultPermissionClassesCheck(BaseSecurityCheck):
    check_id = "wagov_security.D001"
    title = "DRF DEFAULT_PERMISSION_CLASSES should include IsAuthenticated"
    description = (
        "The DRF REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] setting should "
        "include 'rest_framework.permissions.IsAuthenticated' to prevent "
        "unauthenticated access to API endpoints by default."
    )
    category = "drf"
    severity = "critical"

    def run(self, app_configs=None, **kwargs):
        rf = getattr(settings, "REST_FRAMEWORK", {})
        perm_classes = rf.get("DEFAULT_PERMISSION_CLASSES", [])

        # Normalise — could be strings or actual classes
        perm_names = []
        for pc in perm_classes:
            if isinstance(pc, str):
                perm_names.append(pc)
            elif hasattr(pc, "__name__"):
                perm_names.append(f"{pc.__module__}.{pc.__name__}")

        has_is_auth = any("IsAuthenticated" in name for name in perm_names)

        messages = []
        if not perm_classes:
            messages.append(
                self.make_critical(
                    "REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] is empty or not set. "
                    "All API endpoints are accessible without authentication by default.",
                    hint=(
                        'Add "DEFAULT_PERMISSION_CLASSES": '
                        '["rest_framework.permissions.IsAuthenticated"] '
                        "to your REST_FRAMEWORK setting."
                    ),
                )
            )
        elif not has_is_auth:
            messages.append(
                self.make_error(
                    "REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] does not include "
                    "IsAuthenticated. API endpoints may be publicly accessible by default.",
                    hint=(
                        "Include 'rest_framework.permissions.IsAuthenticated' in "
                        "REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']."
                    ),
                )
            )

        return messages


@SecurityCheckRegistry.register
class BrowsableApiRendererCheck(BaseSecurityCheck):
    check_id = "wagov_security.D002"
    title = "BrowsableAPIRenderer should be disabled in production"
    description = (
        "The DRF BrowsableAPIRenderer provides an interactive web UI for "
        "API endpoints. It should not be enabled in production as it exposes "
        "API structure and can aid attackers."
    )
    category = "drf"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        if getattr(settings, "DEBUG", False):
            # Browsable API in debug is acceptable
            return []

        rf = getattr(settings, "REST_FRAMEWORK", {})
        renderers = rf.get("DEFAULT_RENDERER_CLASSES", [])

        renderer_names = []
        for r in renderers:
            if isinstance(r, str):
                renderer_names.append(r)
            elif hasattr(r, "__name__"):
                renderer_names.append(f"{r.__module__}.{r.__name__}")

        has_browsable = any("BrowsableAPIRenderer" in name for name in renderer_names)

        if has_browsable:
            return [
                self.make_warning(
                    "BrowsableAPIRenderer is included in DEFAULT_RENDERER_CLASSES "
                    "in a non-DEBUG environment. This exposes an interactive API UI.",
                    hint=(
                        "Conditionally include BrowsableAPIRenderer only when DEBUG is True. "
                        "Example: if DEBUG: renderers += ('rest_framework.renderers.BrowsableAPIRenderer',)"
                    ),
                )
            ]
        return []
