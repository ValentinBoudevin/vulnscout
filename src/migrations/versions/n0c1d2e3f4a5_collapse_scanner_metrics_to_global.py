"""collapse scanner-origin metrics back to a single global (variant_id NULL) row

Revision ``l8a9b0c1d2e3`` split legacy ``variant_id IS NULL`` CVSS rows into one
copy per related variant. That was wrong for *standard* (scanner) data: a score
coming from NVD/Grype/Yocto is identical for every variant, so it must be stored
once globally (``variant_id IS NULL``) and never duplicated per variant. Only
user-entered ``origin = 'custom'`` scores are variant-scoped.

This migration re-collapses every scanner-origin (``origin <> 'custom'``)
per-variant metric back to a single global row, deleting the duplicates. Custom
rows are left untouched.

Revision ID: n0c1d2e3f4a5
Revises: 7cb28bf85fcc
Create Date: 2026-06-10 00:00:00.000000
"""

import uuid

from alembic import op
import sqlalchemy as sa


revision = 'n0c1d2e3f4a5'
down_revision = '7cb28bf85fcc'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    # Scanner-origin rows that were wrongly scoped to a variant.
    scoped_rows = conn.execute(
        sa.text(
            """
            SELECT id, vulnerability_id, version, score, vector, author, origin
            FROM metrics
            WHERE variant_id IS NOT NULL
              AND (origin IS NULL OR origin <> 'custom')
            """
        )
    ).fetchall()

    for row in scoped_rows:
        params = {
            "vulnerability_id": row.vulnerability_id,
            "version": row.version,
            "score": row.score,
        }

        # Is there already an equivalent global (variant_id IS NULL) row?
        # Match on (vulnerability_id, version, score) only — the same criteria
        # used by Metrics.from_cvss() at runtime — to avoid MultipleResultsFound
        # when rows differ only in vector/author/origin.
        # The `origin <> 'custom'` guard is redundant here (the outer query
        # already filtered those out) but kept as a safety net.
        global_exists = conn.execute(
            sa.text(
                """
                SELECT 1
                FROM metrics
                WHERE variant_id IS NULL
                  AND vulnerability_id = :vulnerability_id
                  AND (version = :version OR (version IS NULL AND :version IS NULL))
                  AND (score = :score OR (score IS NULL AND :score IS NULL))
                  AND (origin IS NULL OR origin <> 'custom')
                LIMIT 1
                """
            ),
            params,
        ).fetchone()

        if not global_exists:
            # Promote this row to global instead of inserting a brand new one.
            conn.execute(
                sa.text("UPDATE metrics SET variant_id = NULL WHERE id = :id"),
                {"id": row.id},
            )
        else:
            # A global row already covers this score: drop the scoped duplicate.
            conn.execute(
                sa.text("DELETE FROM metrics WHERE id = :id"),
                {"id": row.id},
            )


def downgrade():
    # Best-effort reverse: re-split each global scanner-origin row into one copy
    # per variant that observes the vulnerability (mirrors l8a9b0c1d2e3). The
    # original promoted row is removed once at least one per-variant copy exists.
    conn = op.get_bind()

    global_rows = conn.execute(
        sa.text(
            """
            SELECT id, vulnerability_id, version, score, vector, author, origin
            FROM metrics
            WHERE variant_id IS NULL
              AND (origin IS NULL OR origin <> 'custom')
            """
        )
    ).fetchall()

    for row in global_rows:
        related_variants = conn.execute(
            sa.text(
                """
                SELECT DISTINCT s.variant_id
                FROM findings f
                JOIN observations o ON o.finding_id = f.id
                JOIN scans s ON s.id = o.scan_id
                WHERE f.vulnerability_id = :vulnerability_id
                  AND s.variant_id IS NOT NULL
                """
            ),
            {"vulnerability_id": row.vulnerability_id},
        ).fetchall()

        if not related_variants:
            continue

        inserted_any = False
        for variant_row in related_variants:
            conn.execute(
                sa.text(
                    """
                    INSERT INTO metrics
                        (id, vulnerability_id, variant_id, version, score, vector, author, origin)
                    VALUES
                        (:id, :vulnerability_id, :variant_id, :version, :score, :vector, :author, :origin)
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "vulnerability_id": row.vulnerability_id,
                    "variant_id": variant_row.variant_id,
                    "version": row.version,
                    "score": row.score,
                    "vector": row.vector,
                    "author": row.author,
                    "origin": row.origin,
                },
            )
            inserted_any = True

        if inserted_any:
            conn.execute(
                sa.text("DELETE FROM metrics WHERE id = :id"),
                {"id": row.id},
            )
