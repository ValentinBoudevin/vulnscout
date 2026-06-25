# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from unittest.mock import patch
from src.bin.webapp import create_app
from . import write_demo_files, setup_demo_db


@pytest.fixture()
def init_files(tmp_path):
    files = {
        "status": tmp_path / "status.txt",
        "packages": tmp_path / "packages-merged.json",
        "vulnerabilities": tmp_path / "vulnerabilities-merged.json",
        "assessments": tmp_path / "assessments-merged.json",
        "openvex": tmp_path / "openvex.json",
        "time_estimates": tmp_path / "time_estimates.json",
    }
    write_demo_files(files)
    return files


@pytest.fixture()
def app(init_files):
    import os
    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update({
            "TESTING": True,
            "SCAN_FILE": init_files["status"],
            "OPENVEX_FILE": init_files["openvex"],
        })
        setup_demo_db(application)
        yield application
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def existing_cve_id():
    return "CVE-2020-35492"


class TestEpssRefreshEndpoint:

    def test_epss_refresh_returns_200_with_updated_score(self, client, existing_cve_id):
        """POST /api/vulnerabilities/<id>/epss-refresh returns 200 + updated vuln dict."""
        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = {
                "score": 0.75,
                "percentile": 0.95,
            }
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/epss-refresh")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "vulnerabilities" in data
        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == existing_cve_id
        assert vuln["epss"]["score"] == pytest.approx(0.75, abs=1e-4)
        assert vuln["epss"]["percentile"] == pytest.approx(0.95, abs=1e-4)

    def test_epss_refresh_404_unknown_cve(self, client):
        resp = client.post("/api/vulnerabilities/CVE-9999-FAKE/epss-refresh")
        assert resp.status_code == 404
        assert "error" in resp.get_json()

    def test_epss_refresh_503_when_api_returns_none(self, client, existing_cve_id):
        """503 when EPSS API returns no data (None)."""
        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = None
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/epss-refresh")
        assert resp.status_code == 503
        assert "error" in resp.get_json()

    def test_epss_refresh_case_insensitive_cve_id(self, client, existing_cve_id):
        """CVE ID lookup is case-insensitive."""
        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = {
                "score": 0.1, "percentile": 0.5,
            }
            resp = client.post(
                f"/api/vulnerabilities/{existing_cve_id.lower()}/epss-refresh"
            )
        assert resp.status_code == 200

    def test_epss_refresh_sets_data_updated_at_when_score_changes(self, app, client, existing_cve_id):
        """epss_data_updated_at is stamped when the EPSS score changes."""
        from src.models.vulnerability import Vulnerability
        from src.extensions import db
        # Seed a different starting score so the refresh triggers a change
        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            rec.epss_score = None
            rec.epss_data_updated_at = None
            db.session.commit()

        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = {"score": 0.99, "percentile": 0.99}
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/epss-refresh")
        assert resp.status_code == 200

        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            assert rec.epss_data_updated_at is not None

    def test_epss_refresh_no_data_updated_at_when_score_unchanged(self, app, client, existing_cve_id):
        """epss_data_updated_at is NOT stamped when the score is the same."""
        from decimal import Decimal
        from src.models.vulnerability import Vulnerability
        from src.extensions import db
        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            rec.epss_score = Decimal("0.5")
            rec.epss_data_updated_at = None
            db.session.commit()

        with patch("src.routes.vulnerabilities.EPSS_DB") as MockEPSS:
            MockEPSS.return_value.api_get_epss.return_value = {"score": 0.5, "percentile": 0.8}
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/epss-refresh")
        assert resp.status_code == 200

        with app.app_context():
            rec = db.session.get(Vulnerability, existing_cve_id)
            assert rec.epss_data_updated_at is None

