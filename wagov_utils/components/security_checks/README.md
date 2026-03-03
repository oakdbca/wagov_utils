# wagov_utils — Security Checks Component

Automated security checklist for WA Government Django applications.

Integrates with **Django's system checks framework** so checks run automatically on `runserver`, `migrate`, and `manage.py check`. Also provides a standalone management command with detailed, colour-coded reporting.

## Quick Start

### 1. Add to `INSTALLED_APPS`

```python
INSTALLED_APPS += [
    "wagov_utils.components.security_checks",
    # ... other apps
]
```

### 2. Checks run automatically

Every time you run `manage.py runserver`, `manage.py check`, or `manage.py migrate`, the security checks execute as part of Django's system checks framework. Developers **cannot ignore** them — warnings and errors appear in the startup output.

You can also run just the security checks:

```bash
python manage.py check --tag security
```

### 3. Detailed report via management command

```bash
# Run all enabled checks (only failures/warnings shown by default)
python manage.py security_check

# Show all checks including those that passed
python manage.py security_check --show-all

# Show detailed output (issue descriptions and hints) for failures
python manage.py security_check --verbose

# Combine --show-all and --verbose for a full report
python manage.py security_check --show-all --verbose

# Run only specific categories
python manage.py security_check --category settings drf

# Run only specific check IDs
python manage.py security_check --check-id wagov_security.S001 wagov_security.D001

# Include checks disabled by default (e.g. model sanitisation scans)
python manage.py security_check --include-disabled

# List all available checks without running them
python manage.py security_check --list

# Disable colour output (also auto-detected when stdout is not a TTY)
python manage.py security_check --no-color
```

## Output Format

Each check is displayed on a single line with an emoji status indicator:

- ✅ **Pass** — check passed with no issues
- 🟡 **Warning/Info** — non-critical issue(s) found
- ❌ **Error/Critical** — serious issue(s) that should be fixed

With `--verbose`, each issue is expanded with `↳` detail lines showing the specific problem and a hint for how to fix it.

The summary line shows the total count, e.g.:

```
✅ 14 passed, 🟡 3 warnings (17 checks executed)
```

## Registered Checks

### Settings (`settings`)

| ID                    | Severity | Title                                               | Default |
| --------------------- | -------- | --------------------------------------------------- | ------- |
| `wagov_security.S001` | WARNING  | API root view should be hidden                      | Enabled |
| `wagov_security.S002` | ERROR    | SESSION_COOKIE_SECURE should be True                | Enabled |
| `wagov_security.S003` | ERROR    | CSRF_COOKIE_SECURE should be True                   | Enabled |
| `wagov_security.S004` | WARNING  | PRIVATE_MEDIA_STORAGE_LOCATION should be configured | Enabled |
| `wagov_security.S005` | WARNING  | DATA_UPLOAD_MAX_NUMBER_FIELDS should be set         | Enabled |

### DRF Configuration (`drf`)

| ID                    | Severity | Title                                                         | Default |
| --------------------- | -------- | ------------------------------------------------------------- | ------- |
| `wagov_security.D001` | CRITICAL | DRF DEFAULT_PERMISSION_CLASSES should include IsAuthenticated | Enabled |
| `wagov_security.D002` | WARNING  | BrowsableAPIRenderer should be disabled in production         | Enabled |

### ViewSets & APIViews (`viewsets`)

| ID                    | Severity | Title                                                | Default |
| --------------------- | -------- | ---------------------------------------------------- | ------- |
| `wagov_security.V001` | ERROR    | Avoid direct use of ModelViewSet                     | Enabled |
| `wagov_security.V002` | WARNING  | ViewSets should have explicit permission_classes     | Enabled |
| `wagov_security.V003` | WARNING  | APIViews should have explicit permission_classes     | Enabled |
| `wagov_security.V004` | ERROR    | AllowAny should only be used on read-only endpoints  | Enabled |
| `wagov_security.V005` | WARNING  | Custom ViewSet actions should have permission checks | Enabled |

### Media & File Uploads (`media`)

| ID                    | Severity | Title                                                    | Default |
| --------------------- | -------- | -------------------------------------------------------- | ------- |
| `wagov_security.M001` | WARNING  | File upload size limits should be configured             | Enabled |
| `wagov_security.M002` | WARNING  | FileFields should use private storage for sensitive data | Enabled |
| `wagov_security.M003` | WARNING  | File extension whitelist should be enforced              | Enabled |
| `wagov_security.M004` | WARNING  | Private media should have access control                 | Enabled |

### Input Sanitisation (`sanitisation`)

| ID                    | Severity | Title                                                 | Default      |
| --------------------- | -------- | ----------------------------------------------------- | ------------ |
| `wagov_security.N001` | WARNING  | Models with text fields should use input sanitisation | **Disabled** |
| `wagov_security.N002` | WARNING  | Models with JSON fields should sanitise values        | **Disabled** |
| `wagov_security.N003` | INFO     | Client-side cookies should be Secure                  | Enabled      |

> N001 and N002 are disabled by default as they can be noisy — not every model with text/JSON fields is user-facing. Enable them for a thorough audit.

## Configuration

Configure via `SECURITY_CHECKS` in your Django settings:

```python
SECURITY_CHECKS = {
    # Master switch — set to False to disable all checks
    "ENABLED": True,

    # Which apps to scan for ViewSets, APIViews, and models.
    # None (default) = auto-detect from ROOT_URLCONF (e.g. "boranga")
    # ["__all__"]    = scan all installed apps
    # ["app1", ..]   = scan only listed app prefixes
    "SCANNED_APPS": None,

    # Override individual checks (True = force-enable, False = force-disable)
    "CHECKS": {
        "wagov_security.S005": False,     # Disable the DATA_UPLOAD_MAX_NUMBER_FIELDS check
        "wagov_security.N001": True,      # Enable text field sanitisation check
    },

    # Skip scanning certain modules
    "EXCLUDED_MODULES": [
        "some_third_party.api",
    ],

    # Skip scanning certain classes
    "EXCLUDED_CLASSES": [
        "ledger_api_client.api.SystemUserAccountsList",
    ],
}
```

## Adding a New Check

1. Create a new class in the appropriate checker module under `checkers/`, or create a new module.

2. Subclass `BaseSecurityCheck` and register with the registry:

```python
from wagov_utils.components.security_checks.base import BaseSecurityCheck
from wagov_utils.components.security_checks.registry import SecurityCheckRegistry


@SecurityCheckRegistry.register
class MyNewCheck(BaseSecurityCheck):
    check_id = "wagov_security.X001"     # Unique ID
    title = "Short description"           # Shown in reports
    description = "Longer explanation..." # Shown with --list
    category = "my_category"              # Grouping
    severity = "warning"                  # debug|info|warning|error|critical
    enabled_by_default = True

    def run(self, app_configs=None, **kwargs):
        messages = []
        # ... your check logic ...
        if something_is_wrong:
            messages.append(
                self.make_warning(
                    "Description of the problem.",
                    hint="How to fix it.",
                )
            )
        return messages
```

3. If you created a new module, import it in `checkers/__init__.py`.

## Architecture

```
security_checks/
├── __init__.py              # App config
├── apps.py                  # Django AppConfig (registers checks on ready)
├── base.py                  # BaseSecurityCheck class
├── checks.py                # Django system checks integration
├── conf.py                  # Configuration defaults + merging
├── registry.py              # SecurityCheckRegistry (singleton)
├── utils.py                 # Discovery helpers (ViewSets, models)
├── checkers/
│   ├── __init__.py          # Imports all checker modules
│   ├── settings_checks.py   # S001-S005
│   ├── drf_checks.py        # D001-D002
│   ├── viewset_checks.py    # V001-V005
│   ├── media_checks.py      # M001-M004
│   └── sanitisation_checks.py  # N001-N003
└── management/
    └── commands/
        └── security_check.py   # Management command
```

## How It Runs on `runserver`

The `SecurityChecksConfig.ready()` method imports `checks.py`, which registers `_run_all_security_checks` with Django's `Tags.security` system check. Django then runs these automatically on `runserver`, `check`, and `migrate` — developers see warnings/errors in their terminal output and cannot ignore them.
