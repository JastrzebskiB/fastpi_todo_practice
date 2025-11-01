from typing import Any

from pydantic import BaseModel

from .core import app


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
