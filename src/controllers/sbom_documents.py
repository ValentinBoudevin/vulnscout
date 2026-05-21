# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.sbom_document import SBOMDocument
from ._base import ensure_uuid, resolve_entity, validate_non_empty


class SBOMDocumentController:
    """
    Service layer for SBOMDocument CRUD operations.

    Handles input validation, delegates persistence to the :class:`SBOMDocument`
    model and provides dictionary serialisation for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(document: SBOMDocument) -> dict:
        """Return a JSON-serialisable dict representation of *document*."""
        return {
            "id": str(document.id),
            "path": document.path,
            "source_name": document.source_name,
            "format": document.format,
            "scan_id": str(document.scan_id),
        }

    @staticmethod
    def serialize_list(documents: list[SBOMDocument]) -> list[dict]:
        """Return a list of serialised SBOM document dicts."""
        return [SBOMDocumentController.serialize(d) for d in documents]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(document_id: uuid.UUID | str) -> Optional[SBOMDocument]:
        """Return the SBOM document matching *document_id*, or ``None`` if not found."""
        return SBOMDocument.get_by_id(ensure_uuid(document_id))

    @staticmethod
    def get_all() -> list[SBOMDocument]:
        """Return all SBOM documents ordered by path."""
        return SBOMDocument.get_all()

    @staticmethod
    def get_by_scan(scan_id: uuid.UUID | str) -> list[SBOMDocument]:
        """Return all SBOM documents belonging to *scan_id*, ordered by path."""
        return SBOMDocument.get_by_scan(ensure_uuid(scan_id))

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list[SBOMDocument]:
        """Return all SBOM documents belonging to *variant_id* (across all its scans), ordered by path."""
        return SBOMDocument.get_by_variant(ensure_uuid(variant_id))

    @staticmethod
    def get_by_project(project_id: uuid.UUID | str) -> list[SBOMDocument]:
        """Return all SBOM documents belonging to *project_id* (across all variants and scans), ordered by path."""
        return SBOMDocument.get_by_project(ensure_uuid(project_id))

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_fields(path: str, source_name: str) -> tuple[str, str]:
        """Strip and validate *path* and *source_name*."""
        path = validate_non_empty(path, "SBOM document path")
        source_name = validate_non_empty(source_name, "SBOM document source_name")
        return path, source_name

    @staticmethod
    def create(path: str, source_name: str, scan_id: uuid.UUID | str, format: Optional[str] = None) -> SBOMDocument:
        """
        Validate inputs and create a new SBOM document linked to *scan_id*.

        :param format: Optional format hint: 'spdx', 'cdx', 'openvex', or 'yocto_cve_check'.
        :raises ValueError: if *path* or *source_name* is empty or blank.
        """
        path, source_name = SBOMDocumentController._validate_fields(path, source_name)
        return SBOMDocument.create(path, source_name, ensure_uuid(scan_id), format=format)

    @staticmethod
    def update(
        document: SBOMDocument | uuid.UUID | str,
        path: str,
        source_name: str,
        format: Optional[str] = None,
    ) -> SBOMDocument:
        """
        Update *document*'s path, source_name and optional format.  *document* may be a
        :class:`SBOMDocument` instance, a UUID object, or a UUID string.

        :raises ValueError: if *path* or *source_name* is empty or blank,
                            or document is not found.
        """
        path, source_name = SBOMDocumentController._validate_fields(path, source_name)
        resolved = resolve_entity(document, SBOMDocumentController.get, "SBOM document")
        return resolved.update(path, source_name, format=format)

    @staticmethod
    def delete(document: SBOMDocument | uuid.UUID | str) -> None:
        """
        Delete *document*.  *document* may be a :class:`SBOMDocument` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if the document is not found.
        """
        resolved = resolve_entity(document, SBOMDocumentController.get, "SBOM document")
        resolved.delete()
