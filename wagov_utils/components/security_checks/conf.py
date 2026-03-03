"""
Configuration defaults for wagov_utils security checks.

Projects can override these via a SECURITY_CHECKS dict in their Django settings.

Example settings.py usage:

    SECURITY_CHECKS = {
        "ENABLED": True,
        "FAIL_LEVEL": "WARNING",
        "SCANNED_APPS": None,              # None = auto-detect main app from ROOT_URLCONF
                                              # ["myapp", "otherapp"] = explicit list
                                              # ["__all__"] = scan everything
        "CHECKS": {
            "wagov_security.S001": False,   # disable a specific check
        },
        "EXCLUDED_MODULES": [
            "myapp.some_module",            # skip scanning this module
        ],
        "EXCLUDED_CLASSES": [
            "myapp.api.SomeSpecialViewSet", # skip this class
        ],
    }
"""

from django.conf import settings

DEFAULTS = {
    # Master switch — set to False to disable all security checks
    "ENABLED": True,
    # Minimum severity to surface in Django system checks output.
    # One of "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
    "FAIL_LEVEL": "WARNING",
    # Which apps to scan for ViewSets / APIViews / models.
    # None         → auto-detect the main project app from ROOT_URLCONF
    #                (e.g. ROOT_URLCONF="boranga.urls" → scan boranga.* apps only)
    # ["__all__"]  → scan all installed apps (original behaviour)
    # ["app1", ..] → scan only the listed app prefixes
    "SCANNED_APPS": None,
    # Per-check overrides.  Keys are check IDs (e.g. "wagov_security.S001").
    # True  → force-enable
    # False → force-disable
    "CHECKS": {},
    # Dotted module paths to skip when scanning for ViewSets / APIViews / models.
    "EXCLUDED_MODULES": [],
    # Fully qualified class names to skip (e.g. "myapp.api.SomeViewSet").
    "EXCLUDED_CLASSES": [],
}


def get_config():
    """Return the merged security checks configuration."""

    user = getattr(settings, "SECURITY_CHECKS", {})
    merged = {}
    for key, default_value in DEFAULTS.items():
        if key in user:
            if isinstance(default_value, dict):
                merged[key] = {**default_value, **user[key]}
            else:
                merged[key] = user[key]
        else:
            merged[key] = default_value
    return merged
