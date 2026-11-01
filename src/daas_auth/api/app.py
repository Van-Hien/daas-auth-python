from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from daas_auth.api import oauth
from daas_auth.api.auth import authenticated
from daas_auth.api.errors import oauth_error_response
from daas_auth.api.health import public_router
from daas_auth.config import Settings, load_settings
from daas_auth.db import check_strict_mode, make_engine
from daas_auth.domain.errors import OAuthError


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()  # Verify and load settings

    # Connect once now: an unreachable or non-strict database stops the start.
    engine = make_engine(settings.database_url)
    with engine.connect() as connection:
        check_strict_mode(connection)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
        yield  # the server runs here
        engine.dispose()  # on shutdown: close every pooled connection

    # FastAPI serves /docs, /redoc and /openapi.json without a login by default.
    # Default-deny: switched off.
    app = FastAPI(
        title="daas-auth",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.add_exception_handler(OAuthError, oauth_error_response)
    app.include_router(public_router)
    app.include_router(oauth.public_router)
    # Default-deny: every router from here on runs the bearer check first.
    for router in (oauth.router,):
        app.include_router(router, dependencies=[Depends(authenticated)])

    return app
