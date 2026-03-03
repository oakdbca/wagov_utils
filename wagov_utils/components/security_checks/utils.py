"""Utility helpers shared across checker modules."""

import importlib
import inspect
import logging

from django.apps import apps
from django.conf import settings

logger = logging.getLogger(__name__)


def _get_scanned_app_prefixes():
    """Return the list of app module prefixes to scan, or None for all."""
    from .conf import get_config

    scanned = get_config().get("SCANNED_APPS", None)

    if scanned is not None:
        if scanned == ["__all__"]:
            return None  # No filtering — scan everything
        return scanned

    # Auto-detect from ROOT_URLCONF (e.g. "boranga.urls" → "boranga")
    root_urlconf = getattr(settings, "ROOT_URLCONF", "")
    if root_urlconf:
        project_name = root_urlconf.split(".")[0]
        logger.debug(
            "security_checks: auto-detected project app '%s' from ROOT_URLCONF",
            project_name,
        )
        return [project_name]

    return None  # Fallback: scan everything


def _app_matches_prefixes(app_module_name, prefixes):
    """Return True if the app module matches any of the given prefixes."""
    if prefixes is None:
        return True
    return any(app_module_name == prefix or app_module_name.startswith(f"{prefix}.") for prefix in prefixes)


def _get_excluded_modules():
    """Return the set of module paths to skip."""
    from .conf import get_config

    return set(get_config().get("EXCLUDED_MODULES", []))


def _get_excluded_classes():
    """Return the set of fully-qualified class names to skip."""
    from .conf import get_config

    return set(get_config().get("EXCLUDED_CLASSES", []))


def discover_subclasses(base_class, module_suffix="api"):
    """
    Discover all subclasses of *base_class* across installed Django apps.

    Strategy:
    1. For every installed app, try to import ``<app_label>.<module_suffix>``
       (following the convention that DRF endpoints live in ``api.py``).
    2. Also check the app module itself and common alternative names.
    3. Collect every class that is a subclass of *base_class*.

    Returns
    -------
    list[tuple[type, str]]
        List of (cls, module_dotted_path) pairs.
    """
    excluded_modules = _get_excluded_modules()
    excluded_classes = _get_excluded_classes()
    prefixes = _get_scanned_app_prefixes()
    results = []
    seen = set()

    for app_config in apps.get_app_configs():
        app_module = app_config.module.__name__
        if not _app_matches_prefixes(app_module, prefixes):
            continue
        module_paths = []

        # Standard api module
        if module_suffix:
            module_paths.append(f"{app_module}.{module_suffix}")

        # Also check views module (some projects put APIViews there)
        if module_suffix != "views":
            module_paths.append(f"{app_module}.views")

        for mod_path in module_paths:
            if mod_path in excluded_modules:
                continue
            try:
                mod = importlib.import_module(mod_path)
            except (ImportError, Exception):
                continue

            for _name, obj in inspect.getmembers(mod, inspect.isclass):
                if obj is base_class:
                    continue
                fqn = f"{obj.__module__}.{obj.__name__}"
                if fqn in seen or fqn in excluded_classes:
                    continue
                if issubclass(obj, base_class):
                    seen.add(fqn)
                    results.append((obj, mod_path))

    return results


def get_all_models():
    """
    Yield all concrete Django models from installed apps,
    respecting exclusion lists.
    """
    excluded_modules = _get_excluded_modules()
    excluded_classes = _get_excluded_classes()
    prefixes = _get_scanned_app_prefixes()

    for model in apps.get_models():
        mod = model.__module__
        if not _app_matches_prefixes(mod, prefixes):
            continue
        fqn = f"{mod}.{model.__name__}"
        if mod in excluded_modules or fqn in excluded_classes:
            continue
        yield model
