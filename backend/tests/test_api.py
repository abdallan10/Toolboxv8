"""
Tests d'intégration – API Toolbox Pentest
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_modules():
    r = client.get("/api/modules/")
    assert r.status_code in (200, 401)


def test_register_and_login():
    payload = {"username": "testuser", "email": "test@test.com", "password": "Test1234!", "role": "analyst"}
    r = client.post("/api/auth/register", json=payload)
    assert r.status_code in (201, 400)

    login_data = {"username": "testuser", "password": "Test1234!"}
    r = client.post("/api/auth/token", data=login_data)
    if r.status_code == 200:
        assert "access_token" in r.json()


def test_me_unauthenticated():
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_dashboard_stats_unauthenticated():
    r = client.get("/api/dashboard/stats")
    assert r.status_code == 401
