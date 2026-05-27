# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

from .progress_tracker import ProgressTracker

NVDProgressTracker = ProgressTracker(
    default_phase="enrichment",
    completed_message="Enrichment completed successfully",
)
