#!/usr/bin/env python3
"""Exec an injected ASGI runtime against only the provider-local facade factory."""

from __future__ import annotations

import json
import os
import sys
from pathlib import PurePath
from typing import NoReturn

EXPECTED_FACTORY = (
    "api.services.telephony.providers.jambonz.facade.app:create_facade_app"
)
FACTORY_PLACEHOLDER = "{app_factory}"
SHELL_EXECUTABLES = {"ash", "bash", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}


def fail(message: str) -> NoReturn:
    print(f"facade entrypoint: {message}", file=sys.stderr)
    raise SystemExit(64)


def load_command() -> list[str]:
    factory = os.environ.get("FACADE_APP_FACTORY")
    if factory is None:
        fail("FACADE_APP_FACTORY is required")
    if factory != EXPECTED_FACTORY:
        fail("FACADE_APP_FACTORY must name the provider-local facade factory")

    encoded = os.environ.get("FACADE_ASGI_COMMAND_JSON")
    if encoded is None:
        fail("FACADE_ASGI_COMMAND_JSON is required")
    try:
        command = json.loads(encoded)
    except json.JSONDecodeError:
        fail("FACADE_ASGI_COMMAND_JSON must be a JSON argv array")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(argument, str) or not argument for argument in command)
    ):
        fail("FACADE_ASGI_COMMAND_JSON must be a non-empty JSON array of non-empty strings")
    if PurePath(command[0]).name.lower() in SHELL_EXECUTABLES:
        fail("shell runtimes are forbidden")
    if sum(argument.count(FACTORY_PLACEHOLDER) for argument in command) != 1:
        fail("runtime argv must contain exactly one {app_factory} placeholder")
    return [argument.replace(FACTORY_PLACEHOLDER, factory) for argument in command]


def main() -> None:
    command = load_command()
    os.execvpe(command[0], command, os.environ.copy())


if __name__ == "__main__":
    main()
