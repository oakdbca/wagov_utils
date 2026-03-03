# Import all checker modules so they self-register on import.
from . import (  # noqa: F401
    drf_checks,
    media_checks,
    sanitisation_checks,
    settings_checks,
    viewset_checks,
)
