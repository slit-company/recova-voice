from api.schemas.user_configuration import UserConfiguration
from api.services.configuration.merge import merge_user_configurations


def test_merge_user_configurations_preserves_ui_language_when_not_supplied():
    existing = UserConfiguration(ui_language="ko", timezone="Asia/Seoul")

    merged = merge_user_configurations(existing, {"timezone": "UTC"})

    assert merged.timezone == "UTC"
    assert merged.ui_language == "ko"


def test_merge_user_configurations_updates_ui_language_when_supplied():
    existing = UserConfiguration(ui_language="en")

    merged = merge_user_configurations(existing, {"ui_language": "ko"})

    assert merged.ui_language == "ko"
