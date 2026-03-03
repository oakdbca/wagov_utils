"""
Management command: ``python manage.py security_check``

Runs all (or a subset of) WAGOV security checks and prints a detailed
colour-coded report to the terminal.

Usage examples::

    # Run all enabled checks
    python manage.py security_check

    # Show all checks (including disabled / passing)
    python manage.py security_check --show-all

    # Run only specific categories
    python manage.py security_check --category settings drf

    # Run only specific check IDs
    python manage.py security_check --check-id wagov_security.S001 wagov_security.D001

    # Include checks that are disabled by default
    python manage.py security_check --include-disabled

    # List available checks without running them
    python manage.py security_check --list
"""

import sys

from django.core.management.base import BaseCommand
from wagov_utils.components.security_checks.registry import SecurityCheckRegistry


# ANSI colour codes
class _Colours:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"


_SEVERITY_COLOUR = {
    "debug": _Colours.GREY,
    "info": _Colours.CYAN,
    "warning": _Colours.YELLOW,
    "error": _Colours.RED,
    "critical": f"{_Colours.BOLD}{_Colours.RED}",
}

_SEVERITY_LABEL = {
    "debug": "DEBUG",
    "info": "INFO",
    "warning": "WARNING",
    "error": "ERROR",
    "critical": "CRITICAL",
}

# Map Django check message levels to severity strings
_LEVEL_TO_SEVERITY = {
    0: "debug",
    10: "debug",
    20: "info",
    25: "warning",
    30: "warning",
    40: "error",
    50: "critical",
}

# For picking the worst severity when collapsing multiple messages
_SEVERITY_ORDER = {
    "debug": 0,
    "info": 1,
    "warning": 2,
    "error": 3,
    "critical": 4,
}


class Command(BaseCommand):
    help = "Run WAGOV application security checks and print a detailed report."

    def add_arguments(self, parser):
        parser.add_argument(
            "--category",
            nargs="+",
            dest="categories",
            help="Only run checks in these categories (e.g. settings drf viewsets media sanitisation).",
        )
        parser.add_argument(
            "--check-id",
            nargs="+",
            dest="check_ids",
            help="Only run checks with these IDs (e.g. wagov_security.S001).",
        )
        parser.add_argument(
            "--include-disabled",
            action="store_true",
            default=False,
            help="Also run checks that are disabled by default.",
        )
        parser.add_argument(
            "--show-all",
            action="store_true",
            default=False,
            help="Show all checks in the report, including those that passed.",
        )
        parser.add_argument(
            "--list",
            action="store_true",
            default=False,
            dest="list_checks",
            help="List all registered checks and exit (do not run them).",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            default=False,
            dest="verbose",
            help="Show detailed issue descriptions and hints for failing checks.",
        )
        # Note: Django's BaseCommand already provides --no-color.
        # We use that flag (options["no_color"]) instead of adding our own.

    def handle(self, *args, **options):
        # Ensure all checkers are loaded
        from wagov_utils.components.security_checks import checkers  # noqa: F401

        no_colour = options.get("no_color", False) or not sys.stdout.isatty()

        if options["list_checks"]:
            self._list_checks(no_colour)
            return

        checks = self._resolve_checks(options)
        if not checks:
            self.stdout.write("No checks to run.\n")
            return

        self._run_and_report(checks, options, no_colour)

    # ------------------------------------------------------------------

    def _resolve_checks(self, options):
        """Determine which check instances to run."""
        if options["include_disabled"]:
            checks = SecurityCheckRegistry.get_all()
        else:
            checks = SecurityCheckRegistry.get_enabled()

        if options.get("categories"):
            cats = set(options["categories"])
            checks = [c for c in checks if c.category in cats]

        if options.get("check_ids"):
            ids = set(options["check_ids"])
            checks = [c for c in checks if c.check_id in ids]

        return checks

    def _run_and_report(self, checks, options, no_colour):
        """Execute checks, collect results, print report."""
        results_by_check = {}

        for check in sorted(checks, key=lambda c: c.check_id):
            try:
                messages = check.run() or []
            except Exception as exc:
                messages = [
                    check.make_warning(
                        f"Check raised an exception: {exc}",
                        hint="See traceback above for details.",
                    )
                ]
            results_by_check[check.check_id] = {
                "check": check,
                "messages": messages,
            }

        # --- Print report ---
        self._print_header(no_colour)

        passed = 0
        warned = 0
        errored = 0

        # Group results by category for subheadings
        by_category = {}
        for check_id, entry in results_by_check.items():
            cat = entry["check"].category
            by_category.setdefault(cat, []).append(entry)

        # Define a display-friendly category order/name
        _CATEGORY_LABELS = {
            "settings": "Settings",
            "drf": "DRF Configuration",
            "viewsets": "ViewSets & APIViews",
            "media": "Media & File Uploads",
            "sanitisation": "Input Sanitisation",
        }

        for category in sorted(by_category):
            entries = sorted(by_category[category], key=lambda e: e["check"].check_id)
            cat_label = _CATEGORY_LABELS.get(category, category.title())
            self.stdout.write("")
            self.stdout.write(self._c(_Colours.MAGENTA, f"  {cat_label}", no_colour))

            for entry in entries:
                check = entry["check"]
                messages = entry["messages"]

                if not messages:
                    passed += 1
                    if options["show_all"]:
                        self.stdout.write(f"    ✅ {check.check_id}: {check.title}")
                    continue

                # Determine worst severity across all messages for this check
                severity = max(
                    (_LEVEL_TO_SEVERITY.get(m.level, "warning") for m in messages),
                    key=lambda s: _SEVERITY_ORDER.get(s, 2),
                )
                count = len(messages)
                count_suffix = f" ({count} issues)" if count > 1 else ""
                severity_tag = _SEVERITY_LABEL.get(severity, "WARNING")

                if severity in ("error", "critical"):
                    errored += 1
                    icon = "❌"
                else:
                    warned += 1
                    icon = "🟡"

                self.stdout.write(f"    {icon} {check.check_id}: {check.title} [{severity_tag}]{count_suffix}")

                # In verbose mode, expand each issue with its message and hint
                if options.get("verbose"):
                    for msg in messages:
                        self.stdout.write(f"       ↳ {msg.msg}")
                        if msg.hint:
                            hint_text = self._c(_Colours.CYAN, f"Hint: {msg.hint}", no_colour)
                            self.stdout.write(f"         {hint_text}")

        self.stdout.write("")
        self._print_summary(passed, warned, errored, len(checks), no_colour)

        # Exit with non-zero if there are errors/criticals
        if errored > 0:
            sys.exit(1)

    # ------------------------------------------------------------------
    # Printing helpers
    # ------------------------------------------------------------------

    def _c(self, colour, text, no_colour):
        if no_colour:
            return text
        return f"{colour}{text}{_Colours.RESET}"

    def _print_header(self, no_colour):
        self.stdout.write("")
        self.stdout.write(self._c(_Colours.BOLD, "  WAGOV Security Checks", no_colour))
        self.stdout.write(self._c(_Colours.BOLD, f"  {'─' * 50}", no_colour))

    def _print_summary(self, passed, warned, errored, total, no_colour):
        self.stdout.write(self._c(_Colours.BOLD, f"  {'─' * 50}", no_colour))
        parts = []
        if passed:
            parts.append(self._c(_Colours.GREEN, f"✅ {passed} passed", no_colour))
        if warned:
            parts.append(self._c(_Colours.YELLOW, f"🟡 {warned} warnings", no_colour))
        if errored:
            parts.append(self._c(_Colours.RED, f"❌ {errored} errors", no_colour))
        summary = ", ".join(parts) if parts else "No issues found"
        self.stdout.write(f"  {summary} {self._c(_Colours.GREY, f'({total} checks executed)', no_colour)}")
        self.stdout.write("")

    def _list_checks(self, no_colour):
        """Print all registered checks grouped by category."""
        all_checks = SecurityCheckRegistry.get_all()
        if not all_checks:
            self.stdout.write("No security checks registered.\n")
            return

        self._print_header(no_colour)

        by_category = {}
        for check in all_checks:
            by_category.setdefault(check.category, []).append(check)

        for category in sorted(by_category):
            self.stdout.write(f"\n  {self._c(_Colours.MAGENTA, category.upper(), no_colour)}")
            for check in sorted(by_category[category], key=lambda c: c.check_id):
                enabled_icon = "✅" if check.enabled_by_default else "⬜"
                severity_tag = _SEVERITY_LABEL.get(check.severity, "?")
                self.stdout.write(f"    {enabled_icon} {check.check_id}  {check.title}  [{severity_tag}]")

        self.stdout.write("")
        total = len(all_checks)
        enabled_count = sum(1 for c in all_checks if c.enabled_by_default)
        self.stdout.write(f"  {total} checks registered, {enabled_count} enabled by default.\n")
