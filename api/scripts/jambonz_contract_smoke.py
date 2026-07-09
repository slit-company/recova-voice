"""Run supplier-independent Jambonz contract smoke checks."""

from __future__ import annotations

import json
import os



def main() -> int:
    _seed_required_environment_defaults()
    from api.services.telephony.providers.jambonz.simulator_smoke import (
        run_jambonz_contract_smoke,
    )

    result = run_jambonz_contract_smoke()
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    return 0 if result.passed else 1


def _seed_required_environment_defaults() -> None:
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/test_db",
    )
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
    os.environ.setdefault("UI_APP_URL", "http://localhost:3000")
    os.environ.setdefault("MINIO_PUBLIC_ENDPOINT", "http://localhost:9000")


if __name__ == "__main__":
    raise SystemExit(main())
