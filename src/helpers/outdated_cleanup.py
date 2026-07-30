# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Remove records currently classified as outdated.

Package staleness is scoped to a variant: a finding observation is outdated
when its package name/version is absent from that variant's latest SBOM.  The
same package row can be active in a different variant, so this module removes
only stale variant-scoped evidence before pruning records that have become
unreferenced everywhere.
"""

from __future__ import annotations

import uuid

from ..extensions import db
from ..models.assessment import Assessment
from ..models.finding import Finding
from ..models.observation import Observation
from ..models.package import Package
from ..models.project import Project
from ..models.sbom_document import SBOMDocument
from ..models.sbom_observation import SBOMObservation
from ..models.sbom_package import SBOMPackage
from ..models.scan import Scan
from ..models.variant import Variant
from ..models.vulnerability import Vulnerability
from .active_scans import active_sbom_scan_ids_for_variant
from .assessment_staleness import annotate_assessments_outdated

PackageIdentity = tuple[str | None, str | None]
StalePackagePair = tuple[uuid.UUID, uuid.UUID]
UNKNOWN_PROJECT = "Unknown project"
UNKNOWN_VARIANT = "Unknown variant"


def _active_identities_by_variant() -> dict[uuid.UUID, set[PackageIdentity]]:
    """Return active package name/version pairs for every variant."""
    identities_by_variant: dict[uuid.UUID, set[PackageIdentity]] = {}
    for variant in Variant.get_all():
        active_scan_ids = active_sbom_scan_ids_for_variant(variant.id)
        if not active_scan_ids:
            identities_by_variant[variant.id] = set()
            continue
        identities_by_variant[variant.id] = {
            (name, version)
            for name, version in db.session.execute(
                db.select(Package.name, Package.version)
                .join(SBOMPackage, SBOMPackage.package_id == Package.id)
                .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
                .where(SBOMDocument.scan_id.in_(active_scan_ids))
                .distinct()
            )
        }
    return identities_by_variant


def _stale_observations(
    active_identities_by_variant: dict[uuid.UUID, set[PackageIdentity]],
) -> tuple[list[Observation], set[StalePackagePair], set[uuid.UUID]]:
    """Return observations and package/variant pairs matching package staleness."""
    observations: list[Observation] = []
    package_pairs: set[StalePackagePair] = set()
    finding_ids: set[uuid.UUID] = set()
    rows = db.session.execute(
        db.select(Observation, Finding.package_id, Package.name, Package.version, Scan.variant_id)
        .join(Finding, Finding.id == Observation.finding_id)
        .join(Package, Package.id == Finding.package_id)
        .join(Scan, Scan.id == Observation.scan_id)
    )
    for observation, package_id, name, version, variant_id in rows:
        if (name, version) in active_identities_by_variant.get(variant_id, set()):
            continue
        observations.append(observation)
        package_pairs.add((package_id, variant_id))
        finding_ids.add(observation.finding_id)
    return observations, package_pairs, finding_ids


def _outdated_assessments() -> list[dict]:
    """Return custom assessment data matching the public staleness predicate."""
    rows = db.session.execute(
        db.select(
            Assessment.id,
            Assessment.origin,
            Assessment.variant_id,
            Assessment.finding_id,
            Finding.vulnerability_id,
            Package.name,
            Package.version,
            Package.supplier,
        )
        .outerjoin(Finding, Finding.id == Assessment.finding_id)
        .outerjoin(Package, Package.id == Finding.package_id)
        .where(Assessment.origin == "custom", Assessment.variant_id.is_not(None))
    )
    assessments: list[dict] = []
    ids_by_string: dict[str, uuid.UUID] = {}
    for assessment_id, origin, variant_id, finding_id, vulnerability_id, name, version, supplier in rows:
        package_id = f"{name}@{version}" if name is not None else ""
        if package_id and supplier:
            package_id += f"::{supplier}"
        assessments.append({
            "id": str(assessment_id),
            "origin": origin,
            "variant_id": str(variant_id),
            "finding_id": finding_id,
            "vuln_id": vulnerability_id or "",
            "packages": [package_id] if package_id else [],
        })
        ids_by_string[str(assessment_id)] = assessment_id
    annotate_assessments_outdated(assessments)
    return [
        {**assessment, "uuid": ids_by_string[assessment["id"]]}
        for assessment in assessments
        if assessment["outdated"]
    ]


def _stale_sbom_rows(
    model: type[SBOMPackage] | type[SBOMObservation],
    package_pairs: set[StalePackagePair],
) -> list[tuple[SBOMPackage | SBOMObservation, StalePackagePair]]:
    """Return ``(record, (package_id, variant_id))`` rows for stale pairs."""
    package_ids = {package_id for package_id, _ in package_pairs}
    if not package_ids:
        return []
    rows: list[tuple[SBOMPackage | SBOMObservation, StalePackagePair]] = []
    for record, variant_id in db.session.execute(
        db.select(model, Scan.variant_id)
        .join(SBOMDocument, SBOMDocument.id == model.sbom_document_id)
        .join(Scan, Scan.id == SBOMDocument.scan_id)
        .where(model.package_id.in_(package_ids))
    ):
        if record.package_id is None:
            continue
        pair: StalePackagePair = (record.package_id, variant_id)
        if pair in package_pairs:
            rows.append((record, pair))
    return rows


def outdated_data_preview() -> dict[str, list[dict[str, str]]]:
    """Return the stale package data and assessments selected for deletion."""
    stale_observations, package_pairs, _ = _stale_observations(_active_identities_by_variant())
    assessments = _outdated_assessments()
    package_ids = {package_id for package_id, _ in package_pairs}
    variant_ids = {variant_id for _, variant_id in package_pairs}
    variant_ids.update(uuid.UUID(assessment["variant_id"]) for assessment in assessments)
    package_labels = {
        package_id: package.string_id
        for package_id, package in db.session.execute(
            db.select(Package.id, Package).where(Package.id.in_(package_ids))
        )
    } if package_ids else {}
    variant_details = {
        str(variant_id): {"project": project_name, "variant": variant_name}
        for variant_id, project_name, variant_name in db.session.execute(
            db.select(Variant.id, Project.name, Variant.name)
            .join(Project, Project.id == Variant.project_id)
            .where(Variant.id.in_(variant_ids))
        )
    } if variant_ids else {}

    vulnerabilities_by_pair: dict[StalePackagePair, set[str]] = {}
    linked_data_by_pair: dict[StalePackagePair, dict[str, int]] = {}
    observation_ids = [observation.id for observation in stale_observations]
    if observation_ids:
        for package_id, variant_id, vulnerability_id in db.session.execute(
            db.select(Finding.package_id, Scan.variant_id, Finding.vulnerability_id)
            .join(Observation, Observation.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(Observation.id.in_(observation_ids))
        ):
            pair = (package_id, variant_id)
            vulnerabilities_by_pair.setdefault(pair, set()).add(vulnerability_id)
            linked_data_by_pair.setdefault(
                pair, {"observations": 0, "sbom_packages": 0, "sbom_observations": 0}
            )["observations"] += 1
    for _sbom_package, pair in _stale_sbom_rows(SBOMPackage, package_pairs):
        linked_data_by_pair.setdefault(
            pair, {"observations": 0, "sbom_packages": 0, "sbom_observations": 0}
        )["sbom_packages"] += 1
    for _sbom_observation, pair in _stale_sbom_rows(SBOMObservation, package_pairs):
        linked_data_by_pair.setdefault(
            pair, {"observations": 0, "sbom_packages": 0, "sbom_observations": 0}
        )["sbom_observations"] += 1

    packages = [
        {
            "package": package_labels[package_id],
            "project": variant_details.get(str(variant_id), {}).get("project", UNKNOWN_PROJECT),
            "variant": variant_details.get(str(variant_id), {}).get("variant", UNKNOWN_VARIANT),
            "vulnerabilities": sorted(vulnerabilities_by_pair.get((package_id, variant_id), set())),
            "linked_data": linked_data_by_pair.get(
                (package_id, variant_id),
                {"observations": 0, "sbom_packages": 0, "sbom_observations": 0},
            ),
        }
        for package_id, variant_id in sorted(
            package_pairs,
            key=lambda pair: (package_labels[pair[0]], variant_details.get(str(pair[1]), {}).get("variant", "")),
        )
    ]
    return {
        "packages": packages,
        "assessments": [
            {
                "vulnerability": assessment["vuln_id"],
                "package": assessment["packages"][0] if assessment["packages"] else "Unknown package",
                "project": variant_details.get(assessment["variant_id"], {}).get("project", UNKNOWN_PROJECT),
                "variant": variant_details.get(assessment["variant_id"], {}).get("variant", UNKNOWN_VARIANT),
            }
            for assessment in assessments
        ],
    }


def _delete_stale_sbom_records(package_pairs: set[StalePackagePair]) -> tuple[int, int]:
    """Remove SBOM links and SBOM observations for stale package/variant pairs."""
    sbom_packages = [record for record, _ in _stale_sbom_rows(SBOMPackage, package_pairs)]
    sbom_observations = [record for record, _ in _stale_sbom_rows(SBOMObservation, package_pairs)]
    for record in [*sbom_packages, *sbom_observations]:
        db.session.delete(record)
    return len(sbom_packages), len(sbom_observations)


def _delete_orphaned_findings(finding_ids: set[uuid.UUID]) -> tuple[int, set[str]]:
    """Delete candidate findings only when no non-outdated data still needs them."""
    if not finding_ids:
        return 0, set()
    findings = list(db.session.execute(
        db.select(Finding)
        .where(Finding.id.in_(finding_ids))
        .where(~Finding.observations.any())
        .where(~Finding.assessments.any())
        .where(~Finding.time_estimates.any())
    ).scalars())
    vulnerability_ids = {finding.vulnerability_id for finding in findings}
    for finding in findings:
        db.session.delete(finding)
    return len(findings), vulnerability_ids


def _delete_orphaned_vulnerabilities(vulnerability_ids: set[str]) -> int:
    """Delete vulnerability aggregates with no remaining package evidence."""
    if not vulnerability_ids:
        return 0
    vulnerabilities = list(db.session.execute(
        db.select(Vulnerability)
        .where(Vulnerability.id.in_(vulnerability_ids))
        .where(~Vulnerability.findings.any())
        .where(~Vulnerability.sbom_observations.any())
    ).scalars())
    for vulnerability in vulnerabilities:
        db.session.delete(vulnerability)
    return len(vulnerabilities)


def _delete_orphaned_packages(package_pairs: set[StalePackagePair]) -> int:
    """Delete candidate packages only after every related record is gone."""
    package_ids = {package_id for package_id, _ in package_pairs}
    if not package_ids:
        return 0
    packages = list(db.session.execute(
        db.select(Package)
        .where(Package.id.in_(package_ids))
        .where(~Package.findings.any())
        .where(~Package.sbom_packages.any())
        .where(~Package.sbom_observations.any())
    ).scalars())
    for package in packages:
        db.session.delete(package)
    return len(packages)


def delete_outdated_data() -> dict[str, int]:
    """Delete every package observation and custom assessment marked outdated.

    The predicates deliberately mirror ``/api/packages?outdated_only=true``
    and ``annotate_assessments_outdated``.  Shared records are retained until
    no scan, assessment, or SBOM relation references them.
    """
    stale_observations, stale_package_pairs, stale_finding_ids = _stale_observations(
        _active_identities_by_variant()
    )
    outdated_assessments = _outdated_assessments()
    outdated_assessment_ids = [assessment["uuid"] for assessment in outdated_assessments]
    outdated_finding_ids = {
        assessment["finding_id"]
        for assessment in outdated_assessments
        if assessment["finding_id"] is not None
    }
    for assessment_id in outdated_assessment_ids:
        assessment = db.session.get(Assessment, assessment_id)
        if assessment is not None:
            db.session.delete(assessment)
    for observation in stale_observations:
        db.session.delete(observation)
    sbom_packages_deleted, sbom_observations_deleted = _delete_stale_sbom_records(stale_package_pairs)
    db.session.flush()
    findings_deleted, vulnerability_ids = _delete_orphaned_findings(
        stale_finding_ids | outdated_finding_ids
    )
    db.session.flush()
    vulnerabilities_deleted = _delete_orphaned_vulnerabilities(vulnerability_ids)
    db.session.flush()
    packages_deleted = _delete_orphaned_packages(stale_package_pairs)
    db.session.commit()

    return {
        "assessments_deleted": len(outdated_assessment_ids),
        "observations_deleted": len(stale_observations),
        "sbom_packages_deleted": sbom_packages_deleted,
        "sbom_observations_deleted": sbom_observations_deleted,
        "findings_deleted": findings_deleted,
        "vulnerabilities_deleted": vulnerabilities_deleted,
        "packages_deleted": packages_deleted,
    }


_SCAN_CHANGE_FIELDS = (
    "packages_added",
    "packages_removed",
    "packages_upgraded",
    "findings_added",
    "findings_removed",
    "findings_upgraded",
    "vulns_added",
    "vulns_removed",
    "assessments_added",
    "assessments_removed",
)
_STALE_PREVIEW_MESSAGE = "Cleanup preview is no longer current"


def empty_scans_preview() -> list[dict[str, str]]:
    """Return non-initial scans whose complete history diff is empty.

    Uses an uncached scan-history serialisation so destructive cleanup is based
    on the current assessments and findings rather than a stale list response.
    """
    from ..routes._scan_diff import _serialize_list_with_diff

    scans = _serialize_list_with_diff(Scan.get_all())
    return [
        {
            "id": item["id"],
            "description": item["description"] or "",
            "timestamp": item["timestamp"],
            "project": item.get("project_name") or UNKNOWN_PROJECT,
            "variant": item.get("variant_name") or UNKNOWN_VARIANT,
        }
        for item in scans
        if not item.get("is_first")
        and all(item.get(field) == 0 for field in _SCAN_CHANGE_FIELDS)
    ]


def delete_empty_scans() -> dict[str, int]:
    """Delete scans selected by :func:`empty_scans_preview`."""
    scan_ids = [uuid.UUID(scan["id"]) for scan in empty_scans_preview()]
    for scan_id in scan_ids:
        scan = db.session.get(Scan, scan_id)
        if scan is not None:
            db.session.delete(scan)
    db.session.commit()
    return {"scans_deleted": len(scan_ids)}
