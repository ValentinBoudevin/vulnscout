# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .progress_tracker import ProgressTracker


class NVDProgressTracker(ProgressTracker):
    """Singleton tracker for NVD enrichment progress."""

    _default_phase = "enrichment"
    _completed_message = "Enrichment completed successfully"
