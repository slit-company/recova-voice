"""Telephony provider implementations.

Provider registration is explicit and lazy so importing a provider-owned
contract module cannot recursively import every provider. Adding a provider
requires exactly one new module name below.
"""

from __future__ import annotations

import importlib

_PROVIDER_MODULES = (
    "ari",
    "aws_connect",
    "clawops",
    "cloudonix",
    "jambonz",
    "plivo",
    "telnyx",
    "twilio",
    "vobiz",
    "vonage",
)


def register_all() -> None:
    """Import every provider package for its registration side effect."""

    package = __name__
    for module_name in _PROVIDER_MODULES:
        module = importlib.import_module(f"{package}.{module_name}")
        register_provider = getattr(module, "register_provider", None)
        if register_provider is not None:
            register_provider()
