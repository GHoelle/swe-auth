"""Security tests for the session cookie attributes."""

from http.cookies import SimpleCookie

import pytest
from fastapi import Response
from pydantic import ValidationError

from app.config import Settings
from app.security.cookies import (
    SECURE_COOKIE_NAME,
    clear_session_cookie,
    session_cookie_name,
    set_session_cookie,
)

TOKEN = "A" * 43


def _parse_set_cookie(response: Response) -> tuple[str, dict[str, str], str]:
    header = response.headers["set-cookie"]
    cookie = SimpleCookie()
    cookie.load(header)
    ((name, morsel),) = cookie.items()
    attrs = {k.lower(): v for k, v in morsel.items() if v}
    return name, attrs, header


def test_cookie_uses_host_prefix():
    response = Response()
    set_session_cookie(response, TOKEN)
    name, _, _ = _parse_set_cookie(response)
    assert name == SECURE_COOKIE_NAME == "__Host-session"


def test_cookie_is_httponly_so_javascript_cannot_read_it():
    response = Response()
    set_session_cookie(response, TOKEN)
    _, attrs, _ = _parse_set_cookie(response)
    assert attrs.get("httponly") is True


def test_cookie_is_secure_so_it_never_travels_over_plain_http():
    response = Response()
    set_session_cookie(response, TOKEN)
    _, attrs, _ = _parse_set_cookie(response)
    assert attrs.get("secure") is True


def test_cookie_is_samesite_lax_to_block_cross_site_posts():
    response = Response()
    set_session_cookie(response, TOKEN)
    _, attrs, _ = _parse_set_cookie(response)
    assert attrs.get("samesite", "").lower() == "lax"


def test_cookie_meets_host_prefix_rules_path_root_and_no_domain():
    # Browsers silently REJECT a __Host- cookie that has a Domain or a Path other than /.
    response = Response()
    set_session_cookie(response, TOKEN)
    _, attrs, header = _parse_set_cookie(response)
    assert attrs.get("path") == "/"
    assert "domain" not in attrs
    assert "domain=" not in header.lower()


def test_cookie_has_no_max_age_or_expires_server_enforces_lifetime():
    response = Response()
    set_session_cookie(response, TOKEN)
    _, attrs, _ = _parse_set_cookie(response)
    assert "max-age" not in attrs
    assert "expires" not in attrs


def test_clear_cookie_expires_it_with_matching_attributes():
    response = Response()
    clear_session_cookie(response)
    name, attrs, _ = _parse_set_cookie(response)
    assert name == "__Host-session"
    assert attrs.get("max-age") == "0"
    assert attrs.get("path") == "/"
    assert attrs.get("secure") is True
    assert attrs.get("httponly") is True
    assert "domain" not in attrs


def test_insecure_dev_mode_drops_host_prefix_because_browsers_would_reject_it():
    assert session_cookie_name(secure=False) == "session"
    response = Response()
    set_session_cookie(response, TOKEN, secure=False)
    name, attrs, _ = _parse_set_cookie(response)
    assert name == "session"
    assert attrs.get("httponly") is True  # still HttpOnly and SameSite even in dev
    assert attrs.get("samesite", "").lower() == "lax"


def test_production_refuses_insecure_cookies(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    with pytest.raises(ValidationError):
        Settings()


def test_secure_cookies_are_the_default():
    assert Settings().session_cookie_secure is True
