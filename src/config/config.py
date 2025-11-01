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
            f"postgres://{self.db_credentials}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    @property
    def db_credentials(self):
        if self.DB_PASSWORD:
            credentials = f"{self.DB_USERNAME}:``{self.DB_PASSWORD}``"
        else:
            credentials = self.DB_USERNAME
        return credentials
