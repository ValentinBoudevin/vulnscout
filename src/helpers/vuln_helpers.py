# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared validation and persistence helpers for vulnerability CVSS scores
and time-estimate (effort) values.

Used by both ``routes/vulnerabilities.py`` (batch PATCH) and
``helpers/assessment_io.py`` (custom-data import).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from ..models.vulnerability import Vulnerability as _Vulnerability

from ..models import Metrics, CVSS, Iso8601Duration
from ..helpers.verbose import verbose


class Effort(NamedTuple):
    optimistic: int | None
    likely: int | None
    pessimistic: int | None


def _parse_effort_hours(value: int | str | None) -> int:
    """Parse an effort value (ISO 8601 duration string or integer hours) to whole hours."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(Iso8601Duration(value).total_seconds // 3600)
    raise ValueError(f"Invalid effort value: {value!r}")


def validate_effort(eff: dict[str, int | str | None]) -> tuple[Effort, None] | tuple[None, str]:
    """Validate and parse effort dict with optimistic/likely/pessimistic keys.

    Returns ``(effort, None)`` on success or ``(None, error_string) on failure.
    """
    if not all(k in eff for k in ("optimistic", "likely", "pessimistic")):
        return None, "Invalid effort values"
    try:
        opt = _parse_effort_hours(eff["optimistic"])
        lik = _parse_effort_hours(eff["likely"])
        pes = _parse_effort_hours(eff["pessimistic"])
    except (ValueError, TypeError):
        return None, "Invalid effort values"
    if not (opt <= lik <= pes):
        return None, "Invalid effort values"
    return Effort(opt, lik, pes), None


def validate_and_apply_cvss(
    new_cvss: dict[str, str | float],
    record_id: str,
    variant_id: uuid.UUID | None,
    log_prefix: str = "",
) -> str | None:
    """Validate CVSS payload and persist to Metrics.

    Returns an error string on validation failure, ``None`` on success.
    """
    required_keys = {"base_score", "vector_string", "version"}
    if not required_keys.issubset(new_cvss.keys()):
        return "Invalid CVSS data"
    if not new_cvss.get("author"):
        new_cvss["author"] = "unknown"
    if not new_cvss.get("origin"):
        new_cvss["origin"] = "scanner"
    cvss_obj = CVSS.from_dict(new_cvss)
    try:
        Metrics.from_cvss(cvss_obj, record_id, variant_id)
    except Exception as e:
        verbose(f"[{log_prefix} cvss] {e}")
    return None


def apply_effort(
    record: "_Vulnerability", variant_id: uuid.UUID | None,
    effort: Effort,
    log_prefix: str = "",
) -> None:
    """Persist effort values to the first finding's TimeEstimate."""
    try:
        from ..models.time_estimate import TimeEstimate
        for finding in (record.findings or []):
            if variant_id is not None:
                existing = TimeEstimate.get_by_finding_and_variant(finding.id, variant_id)
            else:
                existing = next(
                    (te for te in finding.time_estimates if te.variant_id is None),
                    None,
                )
            if existing is not None:
                existing.update(*effort)
            else:
                TimeEstimate.create(
                    finding_id=finding.id, variant_id=variant_id,
                    optimistic=effort.optimistic, likely=effort.likely, pessimistic=effort.pessimistic
                )
            break
    except Exception as e:
        verbose(f"[{log_prefix} effort] {e}")
