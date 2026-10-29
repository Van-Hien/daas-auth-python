from fastapi import APIRouter

# Public route, no need login
public_router = APIRouter()


@public_router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
