from __future__ import annotations

import argparse
import asyncio
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Sequence

DEFAULT_BASE_URL = "http://localhost:3000"
DEFAULT_OUTPUT_PATH = Path("evidence/returnzero-latency/task-9-fixture.json")
DEFAULT_PREVIEW_PHONE_NUMBER = "+821012345678"


def build_fixture_payload(
    *,
    workflow_id: int,
    session_id: int,
    auth_token: str | None,
    base_url: str,
) -> dict[str, object]:
    return {
        "workflow_id": workflow_id,
        "session_id": session_id,
        "auth_token": auth_token,
        "url": f"{base_url.rstrip('/')}/workflow/{workflow_id}",
    }


def write_fixture_payload(
    *,
    output_path: Path,
    workflow_id: int,
    session_id: int,
    auth_token: str | None,
    base_url: str,
) -> dict[str, object]:
    payload = build_fixture_payload(
        workflow_id=workflow_id,
        session_id=session_id,
        auth_token=auth_token,
        base_url=base_url,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload


async def create_phone_preview_qa_fixture(
    *,
    output_path: Path,
    base_url: str,
    preview_phone_number: str = DEFAULT_PREVIEW_PHONE_NUMBER,
) -> dict[str, object]:
    from api.db import db_client
    from api.schemas.user_configuration import UserConfiguration
    from api.services.configuration.registry import (
        OpenAILLMService,
        OpenAISTTConfiguration,
        OpenAITTSService,
    )
    from api.services.phone_preview.privacy import (
        encrypt_phone,
        global_phone_hash,
        mask_phone,
        phone_hash,
    )
    from api.utils.auth import create_jwt_token

    suffix = uuid.uuid4().hex[:10]
    email = f"phone-preview-qa-{suffix}@recova.local"
    user, _ = await db_client.get_or_create_user_by_provider_id(
        f"phone-preview-qa-user-{suffix}"
    )
    organization, _ = await db_client.get_or_create_organization_by_provider_id(
        f"phone-preview-qa-org-{suffix}",
        user.id,
    )
    await db_client.add_user_to_organization(user.id, organization.id)
    await db_client.update_user_selected_organization(user.id, organization.id)
    await db_client.update_user_configuration(
        user.id,
        UserConfiguration(
            llm=OpenAILLMService(
                api_key="recova-phone-preview-qa-key", model="gpt-4.1-mini"
            ),
            stt=OpenAISTTConfiguration(
                api_key="recova-phone-preview-qa-key", model="gpt-4o-transcribe"
            ),
            tts=OpenAITTSService(
                api_key="recova-phone-preview-qa-key", model="gpt-4o-mini-tts"
            ),
        ),
    )
    workflow_definition = _default_workflow_definition()
    workflow = await db_client.create_workflow(
        name=f"Phone Preview QA {suffix}",
        workflow_definition=workflow_definition,
        user_id=user.id,
        organization_id=organization.id,
    )
    await db_client.save_workflow_draft(
        workflow_id=workflow.id,
        workflow_definition=workflow_definition,
        workflow_configurations={"latency_profile": "balanced"},
        template_context_variables={},
    )
    session = await db_client.create_phone_preview_session(
        organization_id=organization.id,
        user_id=user.id,
        workflow_id=workflow.id,
        phone_number_hash=phone_hash(
            preview_phone_number,
            organization_id=organization.id,
            user_id=user.id,
        ),
        phone_number_global_hash=global_phone_hash(preview_phone_number),
        phone_number_masked=mask_phone(preview_phone_number),
        destination_phone_encrypted=encrypt_phone(preview_phone_number),
        display_name="Phone Preview QA",
        status="verified",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
        max_duration_seconds=300,
    )
    return write_fixture_payload(
        output_path=output_path,
        workflow_id=workflow.id,
        session_id=session.id,
        auth_token=create_jwt_token(user.id, email),
        base_url=base_url,
    )


def _default_workflow_definition() -> dict[str, object]:
    return {
        "nodes": [
            {
                "id": "start",
                "type": "startCall",
                "position": {"x": 0, "y": 0},
                "data": {
                    "name": "Start",
                    "prompt": "You are Recova's concise Korean B2B phone preview agent.",
                    "is_start": True,
                    "greeting": "안녕하세요, Recova 전화 프리뷰입니다. 무엇을 확인해드릴까요?",
                    "greeting_type": "text",
                    "allow_interrupt": True,
                    "delayed_start": False,
                },
            }
        ],
        "edges": [],
    }


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a Recova phone-preview QA fixture."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--base-url",
        default=os.environ.get("RECOVA_QA_FRONTEND_URL", DEFAULT_BASE_URL),
    )
    parser.add_argument("--workflow-id", type=int, default=None)
    parser.add_argument("--session-id", type=int, default=None)
    parser.add_argument(
        "--auth-token",
        default=os.environ.get("RECOVA_QA_AUTH_TOKEN"),
    )
    return parser


def _write_explicit_fixture(args: argparse.Namespace) -> dict[str, object] | None:
    if args.workflow_id is None and args.session_id is None:
        return None
    if args.workflow_id is None or args.session_id is None:
        raise ValueError("--workflow-id and --session-id must be provided together")
    return write_fixture_payload(
        output_path=args.output,
        workflow_id=args.workflow_id,
        session_id=args.session_id,
        auth_token=args.auth_token,
        base_url=args.base_url,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    payload = _write_explicit_fixture(args)
    if payload is None:
        payload = asyncio.run(
            create_phone_preview_qa_fixture(
                output_path=args.output,
                base_url=args.base_url,
            )
        )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
