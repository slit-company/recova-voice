from api.scripts.benchmark_voice_latency import (
    REQUIRED_LATENCY_METRICS,
    measured_returnzero_ttfs_p99_latency_seconds,
    run_mock_benchmark,
)


def test_benchmark_reports_required_latency_fields():
    # Given
    iterations = 5

    # When
    report = run_mock_benchmark(
        profiles=("balanced", "speed_demo"),
        iterations=iterations,
    )

    # Then
    assert set(report.profiles) == {"balanced", "speed_demo"}
    for profile_result in report.profiles.values():
        assert profile_result.iterations == iterations
        assert set(profile_result.metrics) == set(REQUIRED_LATENCY_METRICS)
        for metric in REQUIRED_LATENCY_METRICS:
            summary = profile_result.metrics[metric]
            assert summary.p50_ms > 0
            assert summary.p95_ms >= summary.p50_ms

    json_payload = report.to_jsonable()
    balanced_metrics = json_payload["profiles"]["balanced"]["metrics"]
    assert balanced_metrics["user_stop_to_bot_started_ms"]["p50"] > 0
    assert "user_stop_to_bot_started_ms" not in json_payload["profiles"]["balanced"]


def test_speed_demo_mock_benchmark_improves_by_at_least_400ms():
    # Given
    report = run_mock_benchmark(
        profiles=("balanced", "speed_demo"),
        iterations=20,
    )

    # When
    balanced_p50 = report.profiles["balanced"].metrics[
        "user_stop_to_bot_started_ms"
    ].p50_ms
    speed_p50 = report.profiles["speed_demo"].metrics[
        "user_stop_to_bot_started_ms"
    ].p50_ms

    # Then
    assert balanced_p50 - speed_p50 >= 400


def test_returnzero_ttfs_p99_rounds_up_and_clamps():
    # Given
    vad_stop_to_final_ms = [230.0, 410.0, 1870.0, 3010.0]

    # When
    measured = measured_returnzero_ttfs_p99_latency_seconds(vad_stop_to_final_ms)

    # Then
    assert measured == 3.0
