"""The session cookie: how the session token travels between browser and server.

Each attribute blocks a specific attack:

    HttpOnly     JavaScript can't read the cookie (document.cookie won't show it). If an
                 attacker finds an XSS bug, they can't steal the token and use it from
                 their own machine. (XSS can still make requests *from the victim's page*
                 while it's open, so HttpOnly limits the damage but doesn't cure XSS.)

    Secure       The browser only sends the cookie over HTTPS, so someone on the same
                 coffee-shop Wi-Fi can't sniff it off an unencrypted HTTP request.

    SameSite=Lax The browser doesn't attach the cookie to cross-site POSTs, fetches, or
                 embedded requests. This is the main CSRF defense for now. (Phase 2 adds
                 CSRF tokens as a second layer.) Lax still sends the cookie when the user
                 clicks a normal link to our site, so people arriving from an email link
                 stay logged in. Strict would log them out on every cross-site arrival.

    __Host- prefix  The browser only accepts a cookie with this name if it has Secure,
                 Path=/, and NO Domain attribute. Result: the cookie belongs to exactly
                 one hostname, and a subdomain (say, a compromised blog.example.com)
                 can't set or overwrite it. That blocks "cookie tossing", which is how an
                 attacker would plant a session for session fixation or swapping.

    Path=/       Required by __Host-. The cookie covers the whole app.

    No Max-Age   A "session cookie" in the browser sense: most browsers drop it when fully
                 closed, which helps on shared computers. Real expiry is enforced by the
                 server (idle + absolute timeouts), because a client can keep a cookie as
                 long as it wants.

Local development over plain http://127.0.0.1 still works with Secure cookies in Chrome,
Edge, and Firefox, which treat localhost as a secure context. SESSION_COOKIE_SECURE=false
exists only as an escape hatch, and settings refuse it in production.
"""

from fastapi import Request, Response

SECURE_COOKIE_NAME = "__Host-session"
# Without Secure, the __Host- prefix isn't allowed, so browsers would reject the cookie.
INSECURE_DEV_COOKIE_NAME = "session"


def session_cookie_name(secure: bool) -> str:
    return SECURE_COOKIE_NAME if secure else INSECURE_DEV_COOKIE_NAME


def set_session_cookie(response: Response, token: str, *, secure: bool = True) -> None:
    response.set_cookie(
        key=session_cookie_name(secure),
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        # domain deliberately omitted: host-only cookie (required by __Host-)
        # max_age deliberately omitted: browser-session cookie; server enforces expiry
    )


def clear_session_cookie(response: Response, *, secure: bool = True) -> None:
    """Tell the browser to delete the cookie.

    The attributes must match the ones used to set it, or some browsers treat it as a
    different cookie and keep the original.
    """
    response.delete_cookie(
        key=session_cookie_name(secure),
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )


def read_session_token(request: Request, *, secure: bool = True) -> str | None:
    return request.cookies.get(session_cookie_name(secure))
