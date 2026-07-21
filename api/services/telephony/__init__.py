"""Shared telephony services.

Provider registration is initialized lazily by
``api.services.telephony.registry``. Keeping package import free of provider
side effects allows low-level telephony policy modules to be imported safely
from database and campaign code.
"""
