from fastapi import FastAPI

from daas_auth.api.health import public_router
from daas_auth.config import Settings, load_settings
from daas_auth.db import check_strict_mode, make_engine


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()  # Verify and load settings

    engine = make_engine(settings.database_url)  # Connect once, if failed, stop.
    with engine.connect() as connection:
        check_strict_mode(connection)

    # FastAPI serves /docs, /redoc and /openapi.json without a login by default.
    # Default-deny: switched off.
    app = FastAPI(title="daas-auth", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.include_router(public_router)

    return app
