from urllib.parse import quote

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str
    DB_USERNAME: str
    DB_PASSWORD: str

    class Config:
        env_file = ".env"

    @property
    def db_conn_url(self):
        return (
            "postgresql+psycopg://"  # Ensures we use psycopg3
            f"{self.db_credentials}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    @property
    def db_credentials(self):
        # TODO: Security issue with including the password in the credentials; ok for now since we
        # don't know yet how/when we'll be creating the engine and how we'll deal with connections.
        # Fix this once solutions to the above become crystallized.
        # https://stackoverflow.com/a/68268537
        if self.DB_PASSWORD:
            credentials = f"{self.DB_USERNAME}:{quote(self.DB_PASSWORD)}"
        else:
            credentials = self.DB_USERNAME
        return credentials


# TODO: Consider using get_settings with @lru_cache instead of initializing settings this way
# More info: https://fastapi.tiangolo.com/advanced/settings/#the-main-app-file
settings = Settings()
