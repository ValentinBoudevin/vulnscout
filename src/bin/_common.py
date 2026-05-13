# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared constants and helpers for CLI commands."""

import os

DEFAULT_VARIANT_NAME = "default"


def get_default_author() -> str:
    """Return the author name, reading AUTHOR_NAME at call time."""
    return os.getenv("AUTHOR_NAME", "Savoir-faire Linux")
