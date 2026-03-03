"""
Input sanitisation checks.

Verifies that models with user-facing text fields include sanitisation
measures to prevent XSS and other injection attacks.
"""

import logging

from django.conf import settings
from django.db import models as django_models

from ..base import BaseSecurityCheck
from ..registry import SecurityCheckRegistry
from ..utils import get_all_models

logger = logging.getLogger(__name__)

# Known sanitisation mixin class names (case-insensitive matching)
SANITISE_MIXIN_NAMES = {
    "sanitisefilemixin",
    "sanitisemixin",
    "sanitizemixin",
    "sanitizefilemixin",
    "inputsanitisemixin",
    "inputsanitizemixin",
}

# Field types that store user-provided text and may need sanitisation
TEXT_FIELD_TYPES = (
    django_models.TextField,
    django_models.CharField,
)


def _has_sanitise_mixin(model):
    """Check if any class in the MRO looks like a sanitisation mixin."""
    for cls in model.__mro__:
        if cls.__name__.lower() in SANITISE_MIXIN_NAMES:
            return True
    return False


def _has_text_fields(model):
    """Return the list of text/char fields on the model."""
    text_fields = []
    for field in model._meta.get_fields():
        if isinstance(field, TEXT_FIELD_TYPES):
            text_fields.append(field)
    return text_fields


def _has_json_fields(model):
    """Return the list of JSONFields on the model."""
    json_fields = []
    for field in model._meta.get_fields():
        if isinstance(field, django_models.JSONField):
            json_fields.append(field)
    return json_fields


def _fqn(model):
    return f"{model.__module__}.{model.__name__}"


@SecurityCheckRegistry.register
class TextFieldSanitisationCheck(BaseSecurityCheck):
    check_id = "wagov_security.N001"
    title = "Models with text fields should use input sanitisation"
    description = (
        "Models that store user-provided text (CharField, TextField) should "
        "sanitise input to remove HTML tags and prevent XSS attacks. "
        "A SanitiseMixin or equivalent should be applied."
    )
    category = "sanitisation"
    severity = "warning"
    # Disabled by default as this can be noisy — not every model with text
    # fields is user-facing. Enable it for a thorough audit.
    enabled_by_default = False

    def run(self, app_configs=None, **kwargs):
        messages = []
        for model in get_all_models():
            text_fields = _has_text_fields(model)
            if not text_fields:
                continue

            if not _has_sanitise_mixin(model):
                field_names = ", ".join(f.name for f in text_fields[:5])
                extra = f" (and {len(text_fields) - 5} more)" if len(text_fields) > 5 else ""
                messages.append(
                    self.make_warning(
                        f"{_fqn(model)} has text fields ({field_names}{extra}) but does not use a sanitisation mixin.",
                        hint=(
                            f"Apply a SanitiseMixin to {model.__name__} to strip "
                            "HTML tags from user-provided text fields on save. "
                            "If this model is not user-facing, add it to "
                            "SECURITY_CHECKS['EXCLUDED_CLASSES']."
                        ),
                        obj=model,
                    )
                )
        return messages


@SecurityCheckRegistry.register
class JSONFieldSanitisationCheck(BaseSecurityCheck):
    check_id = "wagov_security.N002"
    title = "Models with JSON fields should sanitise values"
    description = (
        "JSONField values that come from user input should have their "
        "string values sanitised to prevent stored XSS. Keys and values "
        "within JSON structures need individual sanitisation."
    )
    category = "sanitisation"
    severity = "warning"
    # Also disabled by default for the same reason as N001
    enabled_by_default = False

    def run(self, app_configs=None, **kwargs):
        messages = []
        for model in get_all_models():
            json_fields = _has_json_fields(model)
            if not json_fields:
                continue

            if not _has_sanitise_mixin(model):
                field_names = ", ".join(f.name for f in json_fields)
                messages.append(
                    self.make_warning(
                        f"{_fqn(model)} has JSON field(s) ({field_names}) but does not use a sanitisation mixin.",
                        hint=(
                            f"Ensure string values stored in JSON fields on "
                            f"{model.__name__} are sanitised. A SanitiseMixin with "
                            "JSON field support should iterate through all string "
                            "values in the JSON structure and strip script tags."
                        ),
                        obj=model,
                    )
                )
        return messages


@SecurityCheckRegistry.register
class SecureCookieClientSideCheck(BaseSecurityCheck):
    check_id = "wagov_security.N003"
    title = "Client-side cookies should be Secure"
    description = (
        "Any cookies generated in JavaScript code on the client-side should "
        "include 'path=/;secure' to ensure they are only transmitted over "
        "HTTPS. This check is a reminder — automated detection of JavaScript "
        "cookie creation is limited."
    )
    category = "sanitisation"
    severity = "info"
    # This is informational — it cannot be fully automated
    enabled_by_default = True

    def run(self, app_configs=None, **kwargs):
        import glob
        import os
        import re

        messages = []
        base_dir = getattr(settings, "BASE_DIR", None)
        if not base_dir:
            return []

        # Scan JavaScript files for document.cookie assignments
        js_patterns = [
            os.path.join(base_dir, "**", "*.js"),
            os.path.join(base_dir, "**", "*.vue"),
        ]

        cookie_set_pattern = re.compile(r"document\.cookie\s*=", re.IGNORECASE)
        secure_pattern = re.compile(r"secure", re.IGNORECASE)

        insecure_files = set()
        for pattern in js_patterns:
            for filepath in glob.iglob(pattern, recursive=True):
                # Skip node_modules, dist, build, staticfiles
                if any(
                    skip in filepath
                    for skip in (
                        "node_modules",
                        "/dist/",
                        "/build/",
                        "/staticfiles/",
                        "/static/",
                        ".min.js",
                    )
                ):
                    continue

                try:
                    with open(filepath, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                if cookie_set_pattern.search(content):
                    # Check if 'secure' flag is included near the cookie set
                    lines = content.split("\n")
                    for i, line in enumerate(lines):
                        if cookie_set_pattern.search(line):
                            # Check this line and the next few for 'secure'
                            context = "\n".join(lines[max(0, i - 1) : min(len(lines), i + 3)])
                            if not secure_pattern.search(context):
                                rel_path = os.path.relpath(filepath, base_dir)
                                insecure_files.add((rel_path, i + 1))

        for filepath, line_num in sorted(insecure_files):
            messages.append(
                self.make_warning(
                    f"Client-side cookie set at {filepath}:{line_num} may not include the 'secure' flag.",
                    hint=("Ensure all client-side cookies include 'path=/;secure' in the cookie value string."),
                    severity="warning",
                )
            )

        return messages
