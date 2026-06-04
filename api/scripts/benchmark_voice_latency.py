from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import time
import wave
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Sequence, assert_never

LatencyMetricName = Literal[
    "user_stop_to_bot_started_ms",
    "stt_final_ms",
    "llm_ttfb_ms",
    "tts_ttfb_ms",
    "first_response_ms",
]
BenchmarkProfile = Literal["balanced", "speed_demo"]

REQUIRED_LATENCY_METRICS: Final[tuple[LatencyMetricName, ...]] = (
    "user_stop_to_bot_started_ms",
    "stt_final_ms",
    "llm_ttfb_ms",
    "tts_ttfb_ms",
    "first_response_ms",
)
DEFAULT_OUTPUT_PATH: Final = Path("evidence/returnzero-latency/final-benchmark.json")
MIN_RETURNZERO_TTFS_SECONDS: Final = 0.2
MAX_RETURNZERO_TTFS_SECONDS: Final = 3.0


class BenchmarkConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MetricSummary:
    p50_ms: float
    p95_ms: float

    def to_jsonable(self) -> dict[str, float]:
        return {"p50": self.p50_ms, "p95": self.p95_ms}


@dataclass(frozen=True, slots=True)
class MockProfileParameters:
    user_speech_timeout_ms: float
    stt_final_ms: float
    llm_ttfb_ms: float
    tts_ttfb_ms: float
    first_response_ms: float


@dataclass(frozen=True, slots=True)
class ProfileBenchmarkResult:
    iterations: int
    metrics: dict[LatencyMetricName, MetricSummary]

    def to_jsonable(self) -> dict[str, object]:
        return {
            "iterations": self.iterations,
            "metrics": {
                metric: summary.to_jsonable()
                for metric, summary in self.metrics.items()
            },
        }


@dataclass(frozen=True, slots=True)
class ReturnZeroRealBenchmarkResult:
    skipped_real_returnzero: bool
    reason: str | None
    iterations: int
    metrics: dict[str, MetricSummary]
    returnzero_ttfs_p99_latency_seconds: float | None

    def to_jsonable(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "skipped_real_returnzero": self.skipped_real_returnzero,
            "iterations": self.iterations,
            "metrics": {
                metric: summary.to_jsonable()
                for metric, summary in self.metrics.items()
            },
            "returnzero_ttfs_p99_latency_seconds": (
                self.returnzero_ttfs_p99_latency_seconds
            ),
        }
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    schema_version: int
    generated_at: str
    profiles: dict[BenchmarkProfile, ProfileBenchmarkResult]
    real_returnzero: ReturnZeroRealBenchmarkResult | None = None

    def to_jsonable(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "profiles": {
                profile: result.to_jsonable()
                for profile, result in self.profiles.items()
            },
        }
        if self.real_returnzero is not None:
            payload["real_returnzero"] = self.real_returnzero.to_jsonable()
        return payload


def run_mock_benchmark(
    *,
    profiles: Sequence[str],
    iterations: int,
) -> BenchmarkReport:
    if iterations <= 0:
        raise BenchmarkConfigurationError("iterations must be positive")

    profile_results: dict[BenchmarkProfile, ProfileBenchmarkResult] = {}
    for profile_name in profiles:
        profile = _parse_profile(profile_name)
        profile_results[profile] = _run_mock_profile(
            profile=profile,
            iterations=iterations,
        )

    return BenchmarkReport(
        schema_version=1,
        generated_at=datetime.now(UTC).isoformat(),
        profiles=profile_results,
    )


def measured_returnzero_ttfs_p99_latency_seconds(
    vad_stop_to_final_ms: Sequence[float],
) -> float:
    if not vad_stop_to_final_ms:
        raise BenchmarkConfigurationError("vad_stop_to_final_ms must not be empty")

    sorted_values = sorted(vad_stop_to_final_ms)
    p99_index = max(math.ceil(len(sorted_values) * 0.99) - 1, 0)
    p99_seconds = sorted_values[p99_index] / 1000
    rounded_up = math.ceil(p99_seconds * 100) / 100
    return min(
        MAX_RETURNZERO_TTFS_SECONDS,
        max(MIN_RETURNZERO_TTFS_SECONDS, rounded_up),
    )


async def run_returnzero_real_benchmark(
    *,
    iterations: int,
) -> ReturnZeroRealBenchmarkResult:
    if iterations <= 0:
        raise BenchmarkConfigurationError("iterations must be positive")

    missing_env = [
        name
        for name in (
            "RETURNZERO_CLIENT_ID",
            "RETURNZERO_CLIENT_SECRET",
            "RETURNZERO_BENCHMARK_AUDIO",
        )
        if not os.environ.get(name)
    ]
    if missing_env:
        return ReturnZeroRealBenchmarkResult(
            skipped_real_returnzero=True,
            reason=f"missing environment variables: {', '.join(missing_env)}",
            iterations=0,
            metrics={},
            returnzero_ttfs_p99_latency_seconds=None,
        )

    audio_path = Path(os.environ["RETURNZERO_BENCHMARK_AUDIO"])
    if not audio_path.exists():
        return ReturnZeroRealBenchmarkResult(
            skipped_real_returnzero=True,
            reason=f"RETURNZERO_BENCHMARK_AUDIO not found: {audio_path}",
            iterations=0,
            metrics={},
            returnzero_ttfs_p99_latency_seconds=None,
        )

    try:
        audio_payload, sample_rate = _read_benchmark_audio(audio_path)
        vad_stop_to_final_values = [
            await _measure_returnzero_vad_stop_to_final_ms(
                audio_payload=audio_payload,
                sample_rate=sample_rate,
            )
            for _ in range(iterations)
        ]
    except Exception as exc:
        return ReturnZeroRealBenchmarkResult(
            skipped_real_returnzero=True,
            reason=f"real ReturnZero benchmark failed: {type(exc).__name__}: {exc}",
            iterations=0,
            metrics={},
            returnzero_ttfs_p99_latency_seconds=None,
        )

    return ReturnZeroRealBenchmarkResult(
        skipped_real_returnzero=False,
        reason=None,
        iterations=iterations,
        metrics={
            "vad_stop_to_final_ms": _summarize_metric(vad_stop_to_final_values),
        },
        returnzero_ttfs_p99_latency_seconds=(
            measured_returnzero_ttfs_p99_latency_seconds(vad_stop_to_final_values)
        ),
    )


def write_report(*, report: BenchmarkReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_jsonable(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_profiles(raw_profiles: str) -> tuple[BenchmarkProfile, ...]:
    profiles = tuple(
        _parse_profile(part.strip())
        for part in raw_profiles.split(",")
        if part.strip()
    )
    if not profiles:
        raise BenchmarkConfigurationError("at least one profile is required")
    return profiles


def _parse_profile(raw_profile: str) -> BenchmarkProfile:
    match raw_profile:
        case "balanced":
            return "balanced"
        case "speed_demo":
            return "speed_demo"
        case _:
            raise BenchmarkConfigurationError(f"unknown profile: {raw_profile}")


def _run_mock_profile(
    *,
    profile: BenchmarkProfile,
    iterations: int,
) -> ProfileBenchmarkResult:
    parameters = _mock_profile_parameters(profile)
    samples = [_mock_phone_pipeline_sample(parameters, index) for index in range(iterations)]
    return ProfileBenchmarkResult(
        iterations=iterations,
        metrics={
            metric: _summarize_metric([sample[metric] for sample in samples])
            for metric in REQUIRED_LATENCY_METRICS
        },
    )


def _mock_profile_parameters(profile: BenchmarkProfile) -> MockProfileParameters:
    match profile:
        case "balanced":
            return MockProfileParameters(
                user_speech_timeout_ms=600,
                stt_final_ms=380,
                llm_ttfb_ms=265,
                tts_ttfb_ms=240,
                first_response_ms=1120,
            )
        case "speed_demo":
            return MockProfileParameters(
                user_speech_timeout_ms=350,
                stt_final_ms=220,
                llm_ttfb_ms=175,
                tts_ttfb_ms=135,
                first_response_ms=390,
            )
        case unreachable:
            assert_never(unreachable)


def _mock_phone_pipeline_sample(
    parameters: MockProfileParameters,
    iteration: int,
) -> dict[LatencyMetricName, float]:
    jitter = ((iteration % 7) - 3) * 4.0
    stt_final_ms = parameters.stt_final_ms + (jitter * 0.5)
    llm_ttfb_ms = parameters.llm_ttfb_ms + (jitter * 0.35)
    tts_ttfb_ms = parameters.tts_ttfb_ms + (jitter * 0.25)
    return {
        "user_stop_to_bot_started_ms": round(
            parameters.user_speech_timeout_ms
            + stt_final_ms
            + llm_ttfb_ms
            + tts_ttfb_ms,
            3,
        ),
        "stt_final_ms": round(stt_final_ms, 3),
        "llm_ttfb_ms": round(llm_ttfb_ms, 3),
        "tts_ttfb_ms": round(tts_ttfb_ms, 3),
        "first_response_ms": round(parameters.first_response_ms + (jitter * 0.4), 3),
    }


def _summarize_metric(values: Sequence[float]) -> MetricSummary:
    return MetricSummary(
        p50_ms=round(_percentile(values, 0.50), 3),
        p95_ms=round(_percentile(values, 0.95), 3),
    )


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        raise BenchmarkConfigurationError("cannot summarize empty latency samples")
    sorted_values = sorted(values)
    rank = (len(sorted_values) - 1) * percentile
    lower_index = math.floor(rank)
    upper_index = math.ceil(rank)
    if lower_index == upper_index:
        return sorted_values[lower_index]
    lower_weight = upper_index - rank
    upper_weight = rank - lower_index
    return (
        sorted_values[lower_index] * lower_weight
        + sorted_values[upper_index] * upper_weight
    )


def _read_benchmark_audio(audio_path: Path) -> tuple[bytes, int]:
    if audio_path.suffix.lower() == ".wav":
        with wave.open(str(audio_path), "rb") as wave_file:
            return wave_file.readframes(wave_file.getnframes()), wave_file.getframerate()
    return audio_path.read_bytes(), 16000


async def _measure_returnzero_vad_stop_to_final_ms(
    *,
    audio_payload: bytes,
    sample_rate: int,
) -> float:
    from api.services.pipecat.returnzero_stt import (
        RETURNZERO_EOS_MESSAGE,
        ReturnZeroSTTService,
        ReturnZeroSTTSettings,
    )

    service = ReturnZeroSTTService(
        client_id=os.environ["RETURNZERO_CLIENT_ID"],
        client_secret=os.environ["RETURNZERO_CLIENT_SECRET"],
        sample_rate=sample_rate,
        settings=ReturnZeroSTTSettings(model="sommers_ko", language="ko"),
    )
    await service._connect_websocket()
    try:
        websocket = service._get_websocket()
        final_message_task = asyncio.create_task(_wait_for_returnzero_final(websocket))
        chunk_size = max(int(sample_rate * 2 * 0.1), 1)
        for offset in range(0, len(audio_payload), chunk_size):
            await websocket.send(audio_payload[offset : offset + chunk_size])
            await asyncio.sleep(0.1)
        vad_stopped_at = time.perf_counter()
        await websocket.send(RETURNZERO_EOS_MESSAGE)
        final_received_at = await asyncio.wait_for(final_message_task, timeout=15)
        return (final_received_at - vad_stopped_at) * 1000
    finally:
        await service._disconnect_websocket()


async def _wait_for_returnzero_final(websocket) -> float:
    async for message in websocket:
        content = _parse_returnzero_message(message)
        if content is None:
            continue
        if bool(content.get("final")):
            return time.perf_counter()
    raise BenchmarkConfigurationError("ReturnZero websocket closed before final result")


def _parse_returnzero_message(message: str | bytes) -> dict[str, object] | None:
    if isinstance(message, bytes):
        message = message.decode("utf-8")
    try:
        content = json.loads(message)
    except json.JSONDecodeError:
        return None
    if not isinstance(content, dict):
        return None
    return content


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run deterministic Recova voice latency benchmarks."
    )
    parser.add_argument(
        "--profiles",
        default="balanced,speed_demo",
        help="Comma-separated mock profiles to run: balanced,speed_demo.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        help="Number of deterministic mock iterations per profile.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="JSON output path.",
    )
    parser.add_argument(
        "--returnzero-real",
        action="store_true",
        help=(
            "Attempt a real ReturnZero websocket benchmark only when "
            "RETURNZERO_CLIENT_ID, RETURNZERO_CLIENT_SECRET, and "
            "RETURNZERO_BENCHMARK_AUDIO are set."
        ),
    )
    return parser


async def _run_cli_async(args: argparse.Namespace) -> BenchmarkReport:
    report = run_mock_benchmark(
        profiles=parse_profiles(args.profiles),
        iterations=args.iterations,
    )
    if not args.returnzero_real:
        return report

    return BenchmarkReport(
        schema_version=report.schema_version,
        generated_at=report.generated_at,
        profiles=report.profiles,
        real_returnzero=await run_returnzero_real_benchmark(
            iterations=max(min(args.iterations, 5), 1)
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    try:
        args = parser.parse_args(argv)
        report = asyncio.run(_run_cli_async(args))
        write_report(report=report, output_path=args.output)
        print(json.dumps(report.to_jsonable(), ensure_ascii=False, indent=2))
        return 0
    except BenchmarkConfigurationError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
