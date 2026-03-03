"""
Base class for all security checks and severity helpers.

Each concrete check should subclass ``BaseSecurityCheck`` and implement
the ``run`` method, returning a list of ``django.core.checks.CheckMessage``
objects (or an empty list for a pass).
"""

import django.core.checks as dc

# Mapping from human-friendly severity names to Django check message constructors
SEVERITY_MAP = {
    "debug": dc.Debug,
    "info": dc.Info,
    "warning": dc.Warning,
    "error": dc.Error,
    "critical": dc.Critical,
}


class BaseSecurityCheck:
    """
    Abstract base for a single security check.

    Subclasses must set ``check_id``, ``title``, ``category``, and implement ``run()``.
    """

    # Unique ID – follow the pattern wagov_security.XNNN
    # e.g. wagov_security.S001 (settings), wagov_security.V001 (viewsets)
    check_id: str = ""

    # Human-readable short title
    title: str = ""

    # Longer description shown in detail view / management command
    description: str = ""

    # Category grouping: "settings", "drf", "viewsets", "media", "sanitisation"
    category: str = ""

    # Default severity when emitting a Django check message
    severity: str = "warning"  # debug | info | warning | error | critical

    # Whether this check is on by default (can be overridden via SECURITY_CHECKS["CHECKS"])
    enabled_by_default: bool = True

    def run(self, app_configs=None, **kwargs):
        """
        Execute the check.

        Returns
        -------
        list[django.core.checks.CheckMessage]
            Empty list means the check passed.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")

    # ------------------------------------------------------------------
    # Helpers for building Django check messages
    # ------------------------------------------------------------------

    def make_message(self, msg, hint=None, obj=None, severity=None):
        """
        Create a ``django.core.checks.CheckMessage`` with this check's ID.

        Parameters
        ----------
        msg : str
            The problem description.
        hint : str | None
            Optional remediation hint.
        obj : object | None
            The object that caused the message (e.g. a class or setting name).
        severity : str | None
            Override the default severity for this message.
        """
        severity = severity or self.severity
        cls = SEVERITY_MAP.get(severity, dc.Warning)
        return cls(
            msg,
            hint=hint,
            obj=obj,
            id=self.check_id,
        )

    def make_warning(self, msg, **kwargs):
        return self.make_message(msg, severity="warning", **kwargs)

    def make_error(self, msg, **kwargs):
        return self.make_message(msg, severity="error", **kwargs)

    def make_info(self, msg, **kwargs):
        return self.make_message(msg, severity="info", **kwargs)

    def make_critical(self, msg, **kwargs):
        return self.make_message(msg, severity="critical", **kwargs)

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.check_id}>"
