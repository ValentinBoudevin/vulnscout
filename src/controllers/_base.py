# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid


def ensure_uuid(value: uuid.UUID | str) -> uuid.UUID:
    """Normalise *value* to a :class:`uuid.UUID`."""
    if isinstance(value, str):
        return uuid.UUID(value)
    return value


def resolve_entity(entity, getter, label: str = "Record"):
    """Resolve *entity* to a model instance.

    *entity* may already be a model instance, a UUID, or a UUID string.
    *getter* is a callable that accepts a UUID-or-string and returns the
    instance or ``None``.

    :raises ValueError: when the entity cannot be found.
    """
    # If it's not a basic type (UUID / str), assume it's already a model instance.
    if not isinstance(entity, (uuid.UUID, str)):
        return entity
    found = getter(entity)
    if found is None:
        raise ValueError(f"{label} not found.")
    return found


def validate_non_empty(value: str, field_name: str) -> str:
    """Strip *value* and raise :class:`ValueError` if it is blank.

    Returns the stripped string.
    """
    value = value.strip()
    if not value:
        raise ValueError(f"{field_name} must not be empty.")
    return value
