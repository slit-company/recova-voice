from typing import Any, Literal

from fastapi import Depends, HTTPException

from api.constants import (
    AUTH_PROVIDER,
    ENABLE_SELF_SERVE_CAMPAIGNS,
    ENABLE_SELF_SERVE_TELEPHONY,
)
from api.db import db_client
from api.db.models import UserModel
from api.enums import OrganizationConfigurationKey
from api.services.auth.depends import get_user

SelfServeFeature = Literal["telephony", "campaigns"]

_FEATURE_DENY_DETAILS: dict[SelfServeFeature, str] = {
    "telephony": "self_serve_telephony_disabled",
    "campaigns": "self_serve_campaigns_disabled",
}

_FEATURE_CONFIG_KEYS: dict[SelfServeFeature, tuple[str, ...]] = {
    "telephony": (
        "telephony",
        "self_serve_telephony",
        "enable_self_serve_telephony",
    ),
    "campaigns": (
        "campaigns",
        "self_serve_campaigns",
        "enable_self_serve_campaigns",
    ),
}


def _is_local_admin_context() -> bool:
    """Local/OSS auth has no Stack team permission model; treat it as admin-like."""
    return AUTH_PROVIDER == "local"


def _team_permissions_allow(user: UserModel) -> bool:
    """Allow Stack team admins when get_user attached permission metadata.

    Stack's server response shape is provider-controlled, so this intentionally
    accepts a few simple in-memory representations and fails closed otherwise.
    """
    permissions = getattr(user, "team_permissions", None) or getattr(
        user, "permissions", None
    )
    if not permissions:
        return False
    for permission in permissions:
        if isinstance(permission, str) and permission == "admin":
            return True
        if isinstance(permission, dict) and permission.get("id") == "admin":
            return True
        if getattr(permission, "id", None) == "admin":
            return True
    return False


def _global_default_enabled(feature: SelfServeFeature) -> bool:
    if feature == "telephony":
        return ENABLE_SELF_SERVE_TELEPHONY
    return ENABLE_SELF_SERVE_CAMPAIGNS


def _config_value_enables_feature(value: Any, feature: SelfServeFeature) -> bool:
    if value is True:
        return True
    if not isinstance(value, dict):
        return False

    # Org-wide admin/B2B override enables both gated surfaces.
    for key in ("b2b_enabled", "admin_enabled", "self_serve_enabled"):
        if value.get(key) is True:
            return True

    for key in _FEATURE_CONFIG_KEYS[feature]:
        if value.get(key) is True:
            return True

    enabled_features = value.get("enabled_features")
    return isinstance(enabled_features, list) and feature in enabled_features


async def can_access_self_serve_feature(
    user: UserModel, feature: SelfServeFeature
) -> bool:
    if getattr(user, "is_superuser", False):
        return True
    if _team_permissions_allow(user):
        return True
    if _is_local_admin_context():
        return True
    if _global_default_enabled(feature):
        return True

    organization_id = getattr(user, "selected_organization_id", None)
    if not organization_id:
        return False

    config = await db_client.get_configuration(
        organization_id,
        OrganizationConfigurationKey.SELF_SERVE_FEATURES.value,
    )
    return _config_value_enables_feature(config.value if config else None, feature)


async def get_self_serve_feature_gates(user: UserModel) -> dict[str, bool]:
    return {
        "self_serve_telephony": await can_access_self_serve_feature(
            user, "telephony"
        ),
        "self_serve_campaigns": await can_access_self_serve_feature(
            user, "campaigns"
        ),
    }


async def require_self_serve_feature(
    user: UserModel, feature: SelfServeFeature
) -> UserModel:
    if await can_access_self_serve_feature(user, feature):
        return user
    raise HTTPException(status_code=403, detail=_FEATURE_DENY_DETAILS[feature])


async def require_self_serve_telephony(
    user: UserModel = Depends(get_user),
) -> UserModel:
    return await require_self_serve_feature(user, "telephony")


async def require_self_serve_campaigns(
    user: UserModel = Depends(get_user),
) -> UserModel:
    return await require_self_serve_feature(user, "campaigns")
