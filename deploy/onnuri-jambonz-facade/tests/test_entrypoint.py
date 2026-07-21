import importlib.util
import json
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest


EXPECTED_FACTORY = (
    "api.services.telephony.providers.jambonz.facade.app:create_facade_app"
)
ENTRYPOINT_PATH = Path(__file__).parents[1] / "entrypoint.py"


def _load_entrypoint() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "onnuri_jambonz_facade_entrypoint", ENTRYPOINT_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def entrypoint() -> ModuleType:
    return _load_entrypoint()


def _set_environment(
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: ModuleType,
    *,
    factory: str = EXPECTED_FACTORY,
    command: object = None,
) -> dict[str, str]:
    if command is None:
        command = [
            "/opt/facade/bin/uvicorn",
            "{app_factory}",
            "--factory",
            "--host",
            "127.0.0.1",
        ]
    environment = {
        "FACADE_APP_FACTORY": factory,
        "FACADE_ASGI_COMMAND_JSON": json.dumps(command),
        "PATH": "/opt/facade/bin",
    }
    monkeypatch.setattr(entrypoint.os, "environ", environment)
    return environment


def test_main_execs_non_shell_argv_with_the_one_exact_factory_placeholder(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _set_environment(monkeypatch, entrypoint)
    execvpe = Mock(side_effect=RuntimeError("exec intercepted"))
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(RuntimeError, match="^exec intercepted$"):
        entrypoint.main()

    expected_argv = [
        "/opt/facade/bin/uvicorn",
        EXPECTED_FACTORY,
        "--factory",
        "--host",
        "127.0.0.1",
    ]
    execvpe.assert_called_once_with(
        "/opt/facade/bin/uvicorn", expected_argv, environment
    )
    assert expected_argv.count(EXPECTED_FACTORY) == 1


@pytest.mark.parametrize(
    "factory",
    [
        "api.services.telephony.providers.jambonz.facade:create_facade_app",
        "api.services.telephony.providers.jambonz.facade.app:create_app",
        "api.app:app",
        "",
    ],
)
def test_alternate_or_empty_factory_is_rejected_before_exec(
    entrypoint: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    factory: str,
) -> None:
    _set_environment(monkeypatch, entrypoint, factory=factory)
    execvpe = Mock()
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()

    assert exc_info.value.code == 64
    execvpe.assert_not_called()


def test_missing_factory_is_rejected_before_exec(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _set_environment(monkeypatch, entrypoint)
    del environment["FACADE_APP_FACTORY"]
    execvpe = Mock()
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()

    assert exc_info.value.code == 64
    execvpe.assert_not_called()


@pytest.mark.parametrize(
    "command",
    [
        ["uvicorn", "{app_factory}", "{app_factory}", "--factory"],
        ["uvicorn", "prefix-{app_factory}-{app_factory}", "--factory"],
        ["uvicorn", EXPECTED_FACTORY, "--factory"],
    ],
)
def test_duplicate_or_non_placeholder_factory_argv_is_rejected(
    entrypoint: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
) -> None:
    _set_environment(monkeypatch, entrypoint, command=command)
    execvpe = Mock()
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()

    assert exc_info.value.code == 64
    execvpe.assert_not_called()


@pytest.mark.parametrize(
    "shell",
    ["sh", "/bin/bash", "/usr/local/bin/zsh", "DASH"],
)
def test_shell_argv_is_rejected_before_exec(
    entrypoint: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    shell: str,
) -> None:
    _set_environment(
        monkeypatch,
        entrypoint,
        command=[shell, "-c", "exec {app_factory}"],
    )
    execvpe = Mock()
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()

    assert exc_info.value.code == 64
    execvpe.assert_not_called()


@pytest.mark.parametrize(
    "encoded",
    [
        "",
        "not-json",
        "{}",
        "null",
        "[]",
        '["uvicorn", ""]',
        '["uvicorn", 7, "{app_factory}"]',
    ],
)
def test_empty_or_malformed_json_argv_is_rejected_before_exec(
    entrypoint: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    encoded: str,
) -> None:
    environment = _set_environment(monkeypatch, entrypoint)
    environment["FACADE_ASGI_COMMAND_JSON"] = encoded
    execvpe = Mock()
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()

    assert exc_info.value.code == 64
    execvpe.assert_not_called()


def test_missing_json_argv_is_rejected_before_exec(
    entrypoint: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = _set_environment(monkeypatch, entrypoint)
    del environment["FACADE_ASGI_COMMAND_JSON"]
    execvpe = Mock()
    monkeypatch.setattr(entrypoint.os, "execvpe", execvpe)

    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()

    assert exc_info.value.code == 64
    execvpe.assert_not_called()
