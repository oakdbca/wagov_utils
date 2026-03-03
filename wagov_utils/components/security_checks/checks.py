"""
Django system checks integration.

This module registers all enabled security checks with Django's built-in
system checks framework.  Checks run automatically on:
  - ``python manage.py runserver``
  - ``python manage.py check``
  - ``python manage.py migrate``

The tag ``security`` is applied so you can also run them explicitly:
  ``python manage.py check --tag security``
"""

import logging

from django.core.checks import Tags, register

from .registry import SecurityCheckRegistry

logger = logging.getLogger(__name__)


def _run_all_security_checks(app_configs, **kwargs):
    """
    Entry point called by Django's system checks framework.

    Iterates over all enabled security checks and collects messages.
    """
    # The import triggers self-registration of all checker classes.
    from . import checkers  # noqa: F401

    messages = []
    for check in SecurityCheckRegistry.get_enabled():
        try:
            result = check.run(app_configs=app_configs, **kwargs)
            if result:
                messages.extend(result)
        except Exception:
            logger.exception("Security check %s raised an exception", check.check_id)
            messages.append(
                check.make_warning(
                    f"Security check {check.check_id} ({check.title}) "
                    f"raised an unexpected exception. Run with --verbosity 2 for details.",
                    hint="Check the application logs for the full traceback.",
                )
            )
    return messages


# Register with Django — the ``security`` tag lets users run just these:
#   python manage.py check --tag security
register(Tags.security)(_run_all_security_checks)
