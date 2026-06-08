# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from datetime import datetime, timezone

from src.controllers.nvd_progress import NVDProgressTracker
from src.controllers.progress_tracker import ProgressTracker


@pytest.fixture(autouse=True)
def fresh_tracker(monkeypatch):
    """Replace the module-level NVDProgressTracker with a fresh instance for each test."""
    import src.controllers.nvd_progress as mod
    fresh = ProgressTracker(default_phase="enrichment",
                            completed_message="Enrichment completed successfully")
    monkeypatch.setattr(mod, "NVDProgressTracker", fresh)
    yield fresh


def test_initial_state(fresh_tracker):
    tracker = fresh_tracker
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "idle"
    assert data["current"] == 0
    assert data["total"] == 0
    assert data["message"] == "No update in progress"
    assert data["last_update"] is None
    assert data["started_at"] is None


def test_start_default_phase(fresh_tracker):
    tracker = fresh_tracker
    tracker.start()
    data = tracker.get_progress()
    assert data["in_progress"] is True
    assert data["phase"] == "enrichment"
    assert data["started_at"] is not None
    datetime.fromisoformat(data["started_at"])


def test_start_custom_phase(fresh_tracker):
    tracker = fresh_tracker
    tracker.start(phase="nvd_fetch")
    data = tracker.get_progress()
    assert data["phase"] == "nvd_fetch"
    assert data["message"] == "Starting nvd_fetch"


def test_update_progress(fresh_tracker):
    tracker = fresh_tracker
    tracker.start()
    tracker.update("loading", 25, 100, message="Loading CVEs")
    data = tracker.get_progress()
    assert data["in_progress"] is True
    assert data["phase"] == "loading"
    assert data["current"] == 25
    assert data["total"] == 100
    assert data["message"] == "Loading CVEs"
    datetime.fromisoformat(data["last_update"])


def test_update_auto_message(fresh_tracker):
    tracker = fresh_tracker
    tracker.start()
    tracker.update("processing", 3, 10)
    assert tracker.get_progress()["message"] == "processing: 3/10"


def test_complete(fresh_tracker):
    tracker = fresh_tracker
    tracker.start()
    tracker.complete()
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "completed"
    assert "completed" in data["message"].lower()


def test_error(fresh_tracker):
    tracker = fresh_tracker
    tracker.start()
    tracker.error("API timeout")
    data = tracker.get_progress()
    assert data["in_progress"] is False
    assert data["phase"] == "error"
    assert data["message"] == "API timeout"


def test_get_progress_returns_copy(fresh_tracker):
    tracker = fresh_tracker
    tracker.start(phase="test")
    snapshot = tracker.get_progress()
    snapshot["phase"] = "mutated"
    assert tracker.get_progress()["phase"] == "test"


def test_thread_safety(fresh_tracker):
    import threading
    tracker = fresh_tracker
    tracker.start()
    errors = []

    def worker(i):
        try:
            tracker.update("parallel", i, 100)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert tracker.get_progress()["in_progress"] is True


def test_start_if_idle_returns_true_when_idle(fresh_tracker):
    tracker = fresh_tracker
    result = tracker.start_if_idle(phase="test_phase")
    assert result is True
    data = tracker.get_progress()
    assert data["in_progress"] is True
    assert data["phase"] == "test_phase"


def test_start_if_idle_returns_false_when_in_progress(fresh_tracker):
    tracker = fresh_tracker
    tracker.start(phase="running")
    result = tracker.start_if_idle(phase="new_phase")
    assert result is False
    # State must not have changed
    assert tracker.get_progress()["phase"] == "running"


def test_start_if_idle_uses_default_phase(fresh_tracker):
    tracker = fresh_tracker
    tracker.start_if_idle()
    assert tracker.get_progress()["phase"] == "enrichment"


def test_start_if_idle_resets_cancelled_flag(fresh_tracker):
    tracker = fresh_tracker
    tracker.start_if_idle()
    tracker.cancel()
    assert tracker.is_cancelled() is True
    tracker.complete()
    tracker.start_if_idle()
    assert tracker.is_cancelled() is False


def test_start_if_idle_atomic_under_concurrent_calls(fresh_tracker):
    """Only one of N concurrent start_if_idle calls should succeed."""
    import threading
    tracker = fresh_tracker
    successes = []
    barrier = threading.Barrier(10)

    def try_start():
        barrier.wait()
        if tracker.start_if_idle(phase="concurrent"):
            successes.append(1)

    threads = [threading.Thread(target=try_start) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"


