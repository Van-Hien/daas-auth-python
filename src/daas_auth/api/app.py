from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException

from daas_auth.api import oauth, users
from daas_auth.api.auth import authenticated
from daas_auth.api.errors import (
    bearer_error_response,
    http_error_response,
    validation_error_response,
)
from daas_auth.api.health import public_router
from daas_auth.config import Settings, load_settings
from daas_auth.db import check_strict_mode, enforce_foreign_keys, make_engine
from daas_auth.domain.errors import BearerError


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()  # Verify and load settings

    # Connect once now: an unreachable or non-strict database stops the start.
    engine = make_engine(settings.database_url)
    # enforce FK for test DB (SQLite)
    enforce_foreign_keys(engine)
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
    app.add_exception_handler(BearerError, bearer_error_response)
    app.add_exception_handler(HTTPException, http_error_response)
    app.add_exception_handler(RequestValidationError, validation_error_response)
    # Answers the browser's preflight (OPTIONS) and marks each answer as readable
    # for the frontend's origin. The bearer token is a header, so no cookies needed here.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(public_router)
    app.include_router(oauth.public_router)
    # Default-deny: every router from here on runs the bearer check first.
    for router in (oauth.router, users.router):
        app.include_router(router, dependencies=[Depends(authenticated)])

    return app
