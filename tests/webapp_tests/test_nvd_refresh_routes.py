# -*- coding: utf-8 -*-
#
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
            "NVD_DB_PATH": "webapp_tests/mini_nvd.db"
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


class TestSingleCveRefreshEndpoint:

    def test_single_refresh_returns_200_with_vuln_payload(self, client, existing_cve_id):
        """POST /api/vulnerabilities/<id>/nvd-refresh returns 200 + updated vuln dict."""
        mock_details = {
            "description": "updated description",
            "status": "high",
            "attack_vector": "NETWORK",
            "links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
            "weaknesses": ["CWE-79"],
            "publish_date": None,
            "nvd_last_modified": "2025-01-01T00:00:00.000",
            "base_score": 8.1,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_exploitability": 3.9,
            "cvss_impact": 5.2,
        }
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = mock_details
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "vulnerabilities" in data
        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == existing_cve_id
        assert "nvd_fetched_at" in vuln  # timestamp always stamped
        # CVSS score should be reflected in the response
        cvss_scores = vuln["severity"]["cvss"]
        assert any(abs(c["base_score"] - 8.1) < 0.01 for c in cvss_scores)
        # Severity min/max should be populated
        assert vuln["severity"]["max_score"] is not None

    def test_single_refresh_updates_existing_cvss_score(self, client, existing_cve_id):
        """When NVD returns a different score for an existing version, the metric is updated."""
        mock_details = {
            "base_score": 9.8,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = mock_details
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 200
        vuln = resp.get_json()["vulnerabilities"][0]
        cvss_scores = vuln["severity"]["cvss"]
        assert any(abs(c["base_score"] - 9.8) < 0.01 for c in cvss_scores)

    def test_single_refresh_404_unknown_cve(self, client):
        resp = client.post("/api/vulnerabilities/CVE-9999-FAKE/nvd-refresh")
        assert resp.status_code == 404

    def test_single_refresh_503_on_empty_nvd_response(self, client, existing_cve_id):
        """503 when NVD returns 200 but no vulnerability data."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {"vulnerabilities": []})
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 503

    def test_single_refresh_503_on_nvd_failure(self, client, existing_cve_id):
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.side_effect = ConnectionError("NVD unavailable")
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id}/nvd-refresh")
        assert resp.status_code == 503

    def test_single_refresh_case_insensitive_cve_id(self, client, existing_cve_id):
        """CVE ID lookup is case-insensitive."""
        with patch("src.routes.vulnerabilities.NVD_DB") as MockNVD:
            MockNVD.return_value.api_get_cve.return_value = (200, {
                "vulnerabilities": [{"cve": {"id": existing_cve_id}}]
            })
            MockNVD.extract_cve_details.return_value = {}
            resp = client.post(f"/api/vulnerabilities/{existing_cve_id.lower()}/nvd-refresh")
        assert resp.status_code == 200
