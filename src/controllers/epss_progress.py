# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .progress_tracker import ProgressTracker


class EPSSProgressTracker(ProgressTracker):
    """Singleton tracker for EPSS enrichment progress."""

    _default_phase = "epss_enrichment"
    _completed_message = "EPSS enrichment completed successfully"
