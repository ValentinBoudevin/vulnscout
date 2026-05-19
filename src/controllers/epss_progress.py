# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .progress_tracker import ProgressTracker

EPSSProgressTracker = ProgressTracker(
    default_phase="epss_enrichment",
    completed_message="EPSS enrichment completed successfully",
)
