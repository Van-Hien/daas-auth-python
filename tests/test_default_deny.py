import re

from fastapi import FastAPI
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient

# The only routes anyone may call without a token. A new public route goes here.
PUBLIC = {
    ("GET", "/health"),
    ("POST", "/oauth2/user/revoke"),
    ("POST", "/oauth2/user/token"),
    ("POST", "/user/validate_email"),
}


def test_every_other_route_needs_a_token(app: FastAPI, client: TestClient) -> None:
    checked = 0
    # FastAPI 0.162 keeps an included router as one entry in app.routes;
    # iter_route_contexts lists the routes inside, with their full paths.
    for route in iter_route_contexts(app.routes):
        assert route.path is not None  # every route the app registers has a path
        for method in route.methods or ():
            if (method, route.path) in PUBLIC:
                continue
            # /user/{id} -> /user/1
            path = re.sub(r"\{[^}]*\}", "1", route.path)
            response = client.request(method, path)
            assert response.status_code == 401, f"{method} {route.path}"
            checked += 1
    assert checked > 0  # the loop really found routes
