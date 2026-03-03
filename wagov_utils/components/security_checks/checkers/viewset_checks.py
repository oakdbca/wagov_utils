"""
ViewSet and APIView permission checks.

Scans all installed Django apps for DRF ViewSet and APIView subclasses and
verifies that appropriate permission controls are in place.
"""

import logging

from ..base import BaseSecurityCheck
from ..registry import SecurityCheckRegistry
from ..utils import discover_subclasses

logger = logging.getLogger(__name__)


def _has_explicit_permission_classes(cls):
    """
    Return True if *cls* defines ``permission_classes`` directly on itself
    (not just inherited from a parent).
    """
    return "permission_classes" in cls.__dict__


def _get_permission_names(cls):
    """Return a list of permission class names declared on *cls*."""
    perm_classes = getattr(cls, "permission_classes", None) or []
    names = []
    for pc in perm_classes:
        if isinstance(pc, type):
            names.append(pc.__name__)
        elif hasattr(pc, "__class__"):
            names.append(pc.__class__.__name__)
        else:
            names.append(str(pc))
    return names


def _is_readonly_viewset(cls):
    """
    Return True if the class appears to be a read-only ViewSet
    (inherits from ReadOnlyModelViewSet or only mixes in list/retrieve).
    """
    try:
        from rest_framework.viewsets import ReadOnlyModelViewSet

        if issubclass(cls, ReadOnlyModelViewSet):
            return True
    except ImportError:
        pass

    mro_names = [c.__name__ for c in cls.__mro__]
    has_write_mixin = any(name in mro_names for name in ("CreateModelMixin", "UpdateModelMixin", "DestroyModelMixin"))
    return not has_write_mixin


def _fqn(cls):
    return f"{cls.__module__}.{cls.__name__}"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@SecurityCheckRegistry.register
class ModelViewSetCheck(BaseSecurityCheck):
    check_id = "wagov_security.V001"
    title = "Avoid direct use of ModelViewSet"
    description = (
        "viewsets.ModelViewSet provides all CRUD operations by default. "
        "Prefer viewsets.GenericViewSet with explicit mixins to limit "
        "which operations are available."
    )
    category = "viewsets"
    severity = "error"

    def run(self, app_configs=None, **kwargs):
        try:
            from rest_framework.viewsets import ModelViewSet
        except ImportError:
            return []

        found = discover_subclasses(ModelViewSet)
        messages = []
        for cls, mod_path in found:
            # Only flag direct ModelViewSet subclasses – if it subclasses
            # something that already inherits ModelViewSet, the parent
            # is the one to fix.
            direct_parents = cls.__bases__
            if ModelViewSet in direct_parents:
                messages.append(
                    self.make_error(
                        f"{_fqn(cls)} inherits directly from ModelViewSet, exposing all CRUD operations by default.",
                        hint=(
                            f"Refactor {cls.__name__} to inherit from "
                            "viewsets.GenericViewSet with only the mixins required "
                            "(e.g. mixins.RetrieveModelMixin, mixins.ListModelMixin)."
                        ),
                        obj=cls,
                    )
                )
        return messages


@SecurityCheckRegistry.register
class ViewSetPermissionClassesCheck(BaseSecurityCheck):
    check_id = "wagov_security.V002"
    title = "ViewSets should have explicit permission_classes"
    description = (
        "ViewSets without explicit permission_classes that inherit inadequate "
        "permissions (AllowAny or empty) are flagged. ViewSets inheriting "
        "IsAuthenticated or stricter from the DRF default are not flagged."
    )
    category = "viewsets"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        try:
            from rest_framework.viewsets import ViewSetMixin
        except ImportError:
            return []

        found = discover_subclasses(ViewSetMixin)
        messages = []
        for cls, mod_path in found:
            if not _has_explicit_permission_classes(cls):
                effective = _get_effective_permissions(cls)
                if _perms_are_adequate(effective):
                    continue
                messages.append(
                    self.make_warning(
                        f"{_fqn(cls)} does not declare explicit permission_classes "
                        f"and its effective permissions are inadequate "
                        f"({[p.__name__ if hasattr(p, '__name__') else str(p) for p in effective] if effective else 'empty'}).",
                        hint=(f"Add permission_classes = [...] to {cls.__name__} to make access controls explicit."),
                        obj=cls,
                    )
                )
        return messages


@SecurityCheckRegistry.register
class APIViewPermissionClassesCheck(BaseSecurityCheck):
    check_id = "wagov_security.V003"
    title = "APIViews should have explicit permission_classes"
    description = (
        "APIViews without explicit permission_classes that inherit inadequate "
        "permissions (AllowAny or empty) are flagged. Views inheriting "
        "IsAuthenticated or stricter from the DRF default are not flagged."
    )
    category = "viewsets"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        try:
            from rest_framework.views import APIView
            from rest_framework.viewsets import ViewSetMixin
        except ImportError:
            return []

        found = discover_subclasses(APIView)
        messages = []
        for cls, mod_path in found:
            # Skip ViewSets — they are handled by V002
            if issubclass(cls, ViewSetMixin):
                continue
            if not _has_explicit_permission_classes(cls):
                effective = _get_effective_permissions(cls)
                if _perms_are_adequate(effective):
                    continue
                messages.append(
                    self.make_warning(
                        f"{_fqn(cls)} does not declare explicit permission_classes "
                        f"and its effective permissions are inadequate "
                        f"({[p.__name__ if hasattr(p, '__name__') else str(p) for p in effective] if effective else 'empty'}).",
                        hint=(f"Add permission_classes = [...] to {cls.__name__} to make access controls explicit."),
                        obj=cls,
                    )
                )
        return messages


@SecurityCheckRegistry.register
class AllowAnyOnWritableEndpointCheck(BaseSecurityCheck):
    check_id = "wagov_security.V004"
    title = "AllowAny should only be used on read-only endpoints"
    description = (
        "ViewSets or APIViews that use AllowAny should be strictly read-only. "
        "Write operations (create, update, delete) must require authentication."
    )
    category = "viewsets"
    severity = "error"

    def run(self, app_configs=None, **kwargs):
        try:
            from rest_framework.permissions import AllowAny
            from rest_framework.views import APIView
            from rest_framework.viewsets import ViewSetMixin
        except ImportError:
            return []

        messages = []

        # Check ViewSets
        for cls, mod_path in discover_subclasses(ViewSetMixin):
            perm_names = _get_permission_names(cls)
            if "AllowAny" not in perm_names:
                continue
            if not _is_readonly_viewset(cls):
                messages.append(
                    self.make_error(
                        f"{_fqn(cls)} uses AllowAny permissions but is not read-only. "
                        f"Unauthenticated users may be able to create, update, or delete records.",
                        hint=(
                            f"Either restrict {cls.__name__} to ReadOnlyModelViewSet / "
                            "read-only mixins, or replace AllowAny with IsAuthenticated "
                            "and add individual AllowAny to read-only actions."
                        ),
                        obj=cls,
                    )
                )

        # Check APIViews
        for cls, mod_path in discover_subclasses(APIView):
            if issubclass(cls, ViewSetMixin):
                continue
            perm_names = _get_permission_names(cls)
            if "AllowAny" not in perm_names:
                continue
            # Check if the view has write methods
            write_methods = {"post", "put", "patch", "delete"}
            implemented_writes = {m for m in write_methods if m in cls.__dict__}
            if implemented_writes:
                messages.append(
                    self.make_error(
                        f"{_fqn(cls)} uses AllowAny permissions but implements "
                        f"write methods ({', '.join(sorted(implemented_writes))}). "
                        f"Unauthenticated users may be able to modify data.",
                        hint=(
                            f"Restrict write methods in {cls.__name__} to authenticated "
                            "users, or move write operations to a separate view."
                        ),
                        obj=cls,
                    )
                )

        return messages


def _get_effective_permissions(cls):
    """
    Resolve the effective permission_classes for a ViewSet, walking:
      1. Class-level permission_classes attribute
      2. DRF DEFAULT_PERMISSION_CLASSES setting
    Returns the list of permission classes (may be empty).
    """
    # Class-level (explicitly declared, not just inherited from DRF base)
    own_perms = cls.__dict__.get("permission_classes", None)
    if own_perms is not None:
        return list(own_perms)

    # Check MRO for any parent that explicitly sets permission_classes
    for parent in cls.__mro__[1:]:
        if "permission_classes" in parent.__dict__:
            return list(parent.__dict__["permission_classes"])

    # Fall back to DRF default
    try:
        from rest_framework.settings import api_settings

        return list(api_settings.DEFAULT_PERMISSION_CLASSES or [])
    except (ImportError, Exception):
        return []


def _perms_are_adequate(permission_classes):
    """
    Return True if the resolved permission_classes provide at least basic
    authentication protection (i.e. they are not empty and not AllowAny-only).
    """
    try:
        from rest_framework.permissions import AllowAny
    except ImportError:
        return bool(permission_classes)

    if not permission_classes:
        return False

    # If every permission is AllowAny, that's not adequate for write endpoints
    return not all(p is AllowAny or (isinstance(p, type) and issubclass(p, AllowAny)) for p in permission_classes)


@SecurityCheckRegistry.register
class ViewSetCustomActionPermissionsCheck(BaseSecurityCheck):
    check_id = "wagov_security.V005"
    title = "Custom ViewSet actions should have permission checks"
    description = (
        "Custom @action-decorated methods on ViewSets that perform write "
        "operations (POST, PUT, PATCH, DELETE) should have adequate permission "
        "protection. Only warns when the effective inherited permissions are "
        "AllowAny or empty — ViewSets that inherit IsAuthenticated (or stricter) "
        "from the class or DRF defaults are not flagged."
    )
    category = "viewsets"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        try:
            from rest_framework.viewsets import ViewSetMixin
        except ImportError:
            return []

        messages = []
        for cls, mod_path in discover_subclasses(ViewSetMixin):
            # Resolve the effective permissions for this ViewSet once
            effective_perms = _get_effective_permissions(cls)
            viewset_adequate = _perms_are_adequate(effective_perms)

            for attr_name in dir(cls):
                try:
                    attr = getattr(cls, attr_name)
                except AttributeError:
                    continue

                # DRF @action decorator sets these attributes
                if not callable(attr):
                    continue
                mapping = getattr(attr, "mapping", None)
                if mapping is None:
                    continue

                # It's a @action — check if it has write methods
                write_methods = {"post", "put", "patch", "delete"}
                action_methods = set()
                if hasattr(mapping, "keys"):
                    action_methods = {m.lower() for m in mapping.keys() if mapping[m]}
                elif hasattr(attr, "kwargs"):
                    action_methods = {m.lower() for m in attr.kwargs.get("methods", [])}

                has_writes = action_methods & write_methods
                if not has_writes:
                    continue

                # Check if the action specifies its own permission_classes
                action_kwargs = getattr(attr, "kwargs", {})
                action_initkwargs = getattr(attr, "initkwargs", {})
                action_has_own_perms = (
                    "permission_classes" in action_kwargs or "permission_classes" in action_initkwargs
                )

                if action_has_own_perms:
                    # Action explicitly sets permissions — trust it
                    continue

                if viewset_adequate:
                    # The ViewSet (or DRF default) already provides adequate
                    # protection — no need to warn about every action
                    continue

                messages.append(
                    self.make_warning(
                        f"{_fqn(cls)}.{attr_name} is a custom action with write methods "
                        f"({', '.join(sorted(has_writes))}) but neither the action nor "
                        f"its parent ViewSet specify adequate permission_classes.",
                        hint=(
                            f"Add permission_classes=[...] to the @action decorator "
                            f"for {attr_name}, e.g. "
                            f"@action(detail=True, methods=['POST'], "
                            f"permission_classes=[InternalPermission])"
                        ),
                        obj=cls,
                    )
                )

        return messages
