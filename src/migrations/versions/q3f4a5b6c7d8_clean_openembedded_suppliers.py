"""clean OpenEmbedded/OpenEmnedded supplier values in packages

Revision ID: q3f4a5b6c7d8
Revises: p2e3f4a5b6c7
Create Date: 2026-06-18 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'q3f4a5b6c7d8'
down_revision = 'p2e3f4a5b6c7'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    candidate_rows = list(conn.execute(sa.text("""
        SELECT id, name, version, supplier, cpe, purl, licences
        FROM packages
        WHERE lower(coalesce(supplier, '')) LIKE '%openembedded%'
           OR lower(coalesce(supplier, '')) LIKE '%openemnedded%'
    """)).mappings())

    for src in candidate_rows:
        target = conn.execute(sa.text("""
            SELECT id, cpe, purl, licences
            FROM packages
            WHERE name = :name
              AND version = :version
              AND coalesce(supplier, '') = ''
              AND id != :src_id
            LIMIT 1
        """), {
            "name": src["name"],
            "version": src["version"],
            "src_id": src["id"],
        }).mappings().first()

        if target is None:
            conn.execute(sa.text("""
                UPDATE packages
                SET supplier = ''
                WHERE id = :src_id
            """), {"src_id": src["id"]})
            continue

        # Preserve source data when the canonical target row is still empty.
        conn.execute(sa.text("""
            UPDATE packages
            SET cpe = CASE
                    WHEN (cpe IS NULL OR cpe = '[]') AND :src_cpe IS NOT NULL AND :src_cpe != '[]'
                    THEN :src_cpe
                    ELSE cpe
                END,
                purl = CASE
                    WHEN (purl IS NULL OR purl = '[]') AND :src_purl IS NOT NULL AND :src_purl != '[]'
                    THEN :src_purl
                    ELSE purl
                END,
                licences = CASE
                    WHEN (licences IS NULL OR licences = '') AND :src_licences IS NOT NULL AND :src_licences != ''
                    THEN :src_licences
                    ELSE licences
                END
            WHERE id = :target_id
        """), {
            "target_id": target["id"],
            "src_cpe": src["cpe"],
            "src_purl": src["purl"],
            "src_licences": src["licences"],
        })

        # Move SBOM/package links to the canonical row and drop duplicates.
        conn.execute(sa.text("""
            INSERT OR IGNORE INTO sbom_packages (sbom_document_id, package_id)
            SELECT sbom_document_id, :target_id
            FROM sbom_packages
            WHERE package_id = :src_id
        """), {"target_id": target["id"], "src_id": src["id"]})
        conn.execute(sa.text("DELETE FROM sbom_packages WHERE package_id = :src_id"), {"src_id": src["id"]})

        # Observations tied directly to a package can point to the canonical row.
        conn.execute(sa.text("""
            UPDATE sbom_observation
            SET package_id = :target_id
            WHERE package_id = :src_id
        """), {"target_id": target["id"], "src_id": src["id"]})

        source_findings = list(conn.execute(sa.text("""
            SELECT id, vulnerability_id
            FROM findings
            WHERE package_id = :src_id
        """), {"src_id": src["id"]}).mappings())

        for finding in source_findings:
            target_finding = conn.execute(sa.text("""
                SELECT id
                FROM findings
                WHERE package_id = :target_id
                  AND vulnerability_id = :vulnerability_id
                LIMIT 1
            """), {
                "target_id": target["id"],
                "vulnerability_id": finding["vulnerability_id"],
            }).scalar()

            if target_finding is None:
                conn.execute(sa.text("""
                    UPDATE findings
                    SET package_id = :target_id
                    WHERE id = :finding_id
                """), {
                    "target_id": target["id"],
                    "finding_id": finding["id"],
                })
                continue

            conn.execute(sa.text("""
                UPDATE observations
                SET finding_id = :target_finding_id
                WHERE finding_id = :source_finding_id
            """), {
                "target_finding_id": target_finding,
                "source_finding_id": finding["id"],
            })
            conn.execute(sa.text("""
                UPDATE assessments
                SET finding_id = :target_finding_id
                WHERE finding_id = :source_finding_id
            """), {
                "target_finding_id": target_finding,
                "source_finding_id": finding["id"],
            })
            conn.execute(sa.text("""
                UPDATE time_estimates
                SET finding_id = :target_finding_id
                WHERE finding_id = :source_finding_id
            """), {
                "target_finding_id": target_finding,
                "source_finding_id": finding["id"],
            })
            conn.execute(sa.text("DELETE FROM findings WHERE id = :finding_id"), {"finding_id": finding["id"]})

        conn.execute(sa.text("DELETE FROM packages WHERE id = :src_id"), {"src_id": src["id"]})


def downgrade():
    # Data cleanup migration is not reversible.
    pass
