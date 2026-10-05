from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app


def _client_for(monkeypatch, environment: str) -> TestClient:
    monkeypatch.setenv("ENVIRONMENT", environment)
    get_settings.cache_clear()
    # Not using `with TestClient(...)`, so the lifespan (DB/Redis connections) doesn't run.
    return TestClient(create_app())


def test_health_needs_no_dependencies(monkeypatch):
    client = _client_for(monkeypatch, "test")
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_api_docs_disabled_in_production(monkeypatch):
    client = _client_for(monkeypatch, "production")
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_api_docs_enabled_in_development(monkeypatch):
    client = _client_for(monkeypatch, "development")
    assert client.get("/docs").status_code == 200


def test_settings_repr_does_not_leak_secrets(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:supersecretpw@db:5432/auth")
    get_settings.cache_clear()
    assert "supersecretpw" not in repr(get_settings())


def test_environment_must_be_set_explicitly(monkeypatch):
    """Fail closed: a deploy that forgets ENVIRONMENT must not silently run as development."""
    import pytest
    from pydantic import ValidationError

    from app.config import Settings

    monkeypatch.delenv("ENVIRONMENT", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_session_timeout_defaults_match_owasp_ranges():
    from app.config import Settings

    settings = Settings()
    assert 15 * 60 <= settings.session_idle_timeout_seconds <= 30 * 60
    assert 4 * 3600 <= settings.session_absolute_timeout_seconds <= 8 * 3600
