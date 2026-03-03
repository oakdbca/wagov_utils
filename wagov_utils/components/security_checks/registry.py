"""
Registry that collects all security check classes and resolves which are enabled.
"""

import logging

from .conf import get_config

logger = logging.getLogger(__name__)


class SecurityCheckRegistry:
    """Singleton-style registry – check classes are stored on the class itself."""

    _checks: dict = {}  # check_id → check_class

    @classmethod
    def register(cls, check_class):
        """
        Register a check class (or use as a decorator).

        Usage::

            @SecurityCheckRegistry.register
            class MyCheck(BaseSecurityCheck):
                check_id = "wagov_security.X001"
                ...
        """
        check_id = check_class.check_id
        if not check_id:
            raise ValueError(f"{check_class.__name__} must define a non-empty check_id")
        if check_id in cls._checks:
            logger.debug(
                "Security check %s re-registered by %s",
                check_id,
                check_class.__name__,
            )
        cls._checks[check_id] = check_class
        return check_class

    @classmethod
    def get_all(cls):
        """Return all registered check instances, regardless of enabled state."""
        return [klass() for klass in cls._checks.values()]

    @classmethod
    def get_enabled(cls):
        """
        Return check instances that should run according to the current config.

        Resolution order:
        1. ``SECURITY_CHECKS["CHECKS"][check_id]`` overrides everything.
        2. Otherwise, the class's ``enabled_by_default`` is used.
        """
        config = get_config()
        if not config.get("ENABLED", True):
            return []

        overrides = config.get("CHECKS", {})
        enabled = []
        for check_id, klass in cls._checks.items():
            if check_id in overrides:
                if overrides[check_id]:
                    enabled.append(klass())
            elif klass.enabled_by_default:
                enabled.append(klass())
        return enabled

    @classmethod
    def get_by_category(cls, category):
        """Return all checks (enabled or not) for a given category."""
        return [klass() for klass in cls._checks.values() if klass.category == category]

    @classmethod
    def get_categories(cls):
        """Return the set of all registered categories."""
        return sorted({klass.category for klass in cls._checks.values()})

    @classmethod
    def clear(cls):
        """Remove all registered checks (useful for testing)."""
        cls._checks.clear()
