from collections.abc import Callable
from typing import Any

from fastapi import Request
from pydantic import BaseModel

from .core import app
from .auth.views import router as auth_router

app.include_router(auth_router)


# Uncomment if debugging of payloads or routing is needed. This middleware is intentionally 
# commented out to speed up the app.
# @app.middleware("http")
async def debug_middleware(request: Request, call_next: Callable):
    debugged_paths = []
    if request.url.path not in debugged_paths:
        response = await call_next(request)
        return response
    else:
        try:
            body = await request.body()
            body_json = await request.json()
        except Exception as e:
            pass
        breakpoint()
    


class TestModel(BaseModel):
    name: str
    description: str | None = "some default"
    some_number: int = 42


@app.get("/")
async def root() -> Any:  # Any just for testing
    from .core import settings
    return [
        TestModel(name="test", description="non-default description"),
        TestModel(name="another one", some_number=1337),
        TestModel(
            name="here go config", 
            description=settings.db_conn_url,
            some_number=settings.DB_PORT,
        )
    ]


if __name__ == "__main__":
    app.run()
