"""
Private media storage and file upload security checks.

Verifies that:
- File uploads are validated against a whitelist
- File size limits are configured
- Private media is stored securely with access controls
"""

from django.conf import settings
from django.db import models as django_models

from ..base import BaseSecurityCheck
from ..registry import SecurityCheckRegistry
from ..utils import get_all_models


@SecurityCheckRegistry.register
class FileUploadSizeLimitCheck(BaseSecurityCheck):
    check_id = "wagov_security.M001"
    title = "File upload size limits should be configured"
    description = (
        "MAX_UPLOAD_SIZE_BYTES (or FILE_UPLOAD_MAX_MEMORY_SIZE / "
        "DATA_UPLOAD_MAX_MEMORY_SIZE) should be configured to prevent "
        "users from uploading excessively large files."
    )
    category = "media"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        has_custom_limit = hasattr(settings, "MAX_UPLOAD_SIZE_BYTES")
        file_upload_limit = getattr(settings, "FILE_UPLOAD_MAX_MEMORY_SIZE", None)
        data_upload_limit = getattr(settings, "DATA_UPLOAD_MAX_MEMORY_SIZE", None)

        messages = []
        if not has_custom_limit and file_upload_limit is None:
            messages.append(
                self.make_warning(
                    "No explicit file upload size limit is configured. "
                    "Consider setting MAX_UPLOAD_SIZE_BYTES in settings.py.",
                    hint=(
                        "Add MAX_UPLOAD_SIZE_BYTES = env('MAX_UPLOAD_SIZE_BYTES', "
                        "20 * 1024 * 1024) to settings.py and enforce it in "
                        "your file upload handling."
                    ),
                )
            )

        return messages


@SecurityCheckRegistry.register
class FileFieldStorageCheck(BaseSecurityCheck):
    check_id = "wagov_security.M002"
    title = "FileFields should use private storage for sensitive data"
    description = (
        "Models with FileField or ImageField should use a private storage "
        "backend (not default public media storage) if the files could "
        "contain sensitive information."
    )
    category = "media"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        messages = []
        default_storage_class_name = None

        try:
            from django.core.files.storage import default_storage

            default_storage_class_name = type(default_storage).__name__
        except Exception:
            pass

        for model in get_all_models():
            for field in model._meta.get_fields():
                if not isinstance(field, (django_models.FileField, django_models.ImageField)):
                    continue

                storage = getattr(field, "storage", None)
                if storage is None:
                    continue

                storage_name = type(storage).__name__
                storage_location = getattr(storage, "location", "")

                # Check if using default storage (typically public)
                uses_default = storage_name == default_storage_class_name
                # Check if the storage location includes a private-media path
                looks_private = any(
                    marker in str(storage_location).lower() for marker in ("private", "secure", "protected")
                )

                if uses_default and not looks_private:
                    fqn = f"{model.__module__}.{model.__name__}"
                    messages.append(
                        self.make_info(
                            f"{fqn}.{field.name} uses default (public) storage. "
                            f"If this field stores sensitive files, consider using "
                            f"a private storage backend.",
                            hint=(
                                "Use FileSystemStorage(location=settings.PRIVATE_MEDIA_STORAGE_LOCATION) "
                                "for the storage parameter of sensitive FileFields."
                            ),
                        )
                    )

        return messages


@SecurityCheckRegistry.register
class FileExtensionWhitelistCheck(BaseSecurityCheck):
    check_id = "wagov_security.M003"
    title = "File extension whitelist should be enforced"
    description = (
        "Uploaded files should be validated against an approved file extension "
        "whitelist. This prevents users from uploading potentially dangerous "
        "file types."
    )
    category = "media"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        # Look for evidence of a whitelist check being configured
        # This could be a model, a setting, or a helper function

        # Check for common whitelist setting patterns
        has_whitelist_setting = any(
            hasattr(settings, attr)
            for attr in (
                "FILE_EXTENSION_WHITELIST",
                "ALLOWED_FILE_EXTENSIONS",
                "UPLOAD_ALLOWED_EXTENSIONS",
            )
        )

        # Check for a whitelist model (like Boranga's FileExtensionWhitelist)
        has_whitelist_model = False
        for model in get_all_models():
            model_name = model.__name__.lower()
            if "whitelist" in model_name and ("file" in model_name or "extension" in model_name):
                has_whitelist_model = True
                break

        # Check for common whitelist-related cache keys
        has_whitelist_cache = hasattr(settings, "CACHE_KEY_FILE_EXTENSION_WHITELIST")

        if not (has_whitelist_setting or has_whitelist_model or has_whitelist_cache):
            return [
                self.make_warning(
                    "No file extension whitelist mechanism detected. "
                    "Uploaded files may not be validated for allowed file types.",
                    hint=(
                        "Implement a file extension whitelist, either as a Django setting "
                        "(FILE_EXTENSION_WHITELIST), a database model, or a validation "
                        "function applied to all file upload endpoints."
                    ),
                )
            ]
        return []


@SecurityCheckRegistry.register
class PrivateMediaAccessControlCheck(BaseSecurityCheck):
    check_id = "wagov_security.M004"
    title = "Private media should have access control"
    description = (
        "Private media files should be served through Django views that "
        "check user authorisation, not directly by the web server. The "
        "private media directory should not be served as a static path."
    )
    category = "media"
    severity = "warning"

    def run(self, app_configs=None, **kwargs):
        # Check if MEDIA_URL is configured in a way that might expose private files
        media_url = getattr(settings, "MEDIA_URL", "")
        media_root = getattr(settings, "MEDIA_ROOT", "")

        private_location = getattr(settings, "PRIVATE_MEDIA_STORAGE_LOCATION", None) or getattr(
            settings, "PRIVATE_MEDIA_ROOT", None
        )

        messages = []

        if private_location:
            # Check that private media root is not inside MEDIA_ROOT
            private_str = str(private_location)
            media_str = str(media_root)
            if media_str and private_str.startswith(media_str):
                messages.append(
                    self.make_error(
                        "PRIVATE_MEDIA_STORAGE_LOCATION is inside MEDIA_ROOT. "
                        "Private files may be served directly by the web server.",
                        hint=(
                            "Move PRIVATE_MEDIA_STORAGE_LOCATION outside of MEDIA_ROOT "
                            "to ensure private files are only accessible through "
                            "Django views with authorisation checks."
                        ),
                    )
                )

        return messages
