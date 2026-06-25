# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .progress_tracker import ProgressTracker

GHSAProgressTracker = ProgressTracker(
    default_phase="ghsa_enrichment",
    completed_message="GHSA enrichment completed successfully",
)
