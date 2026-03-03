from django.apps import AppConfig


class SecurityChecksConfig(AppConfig):
    name = "wagov_utils.components.security_checks"
    label = "wagov_security_checks"
    verbose_name = "WA Gov Security Checks"

    def ready(self):
        # Import checks module to register all checks with Django's system checks framework
        from . import checks  # noqa: F401
