from pytest import fixture
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError


TEST_DB_NAME = "fastapi_todo_test"


@fixture(scope="module")
def test_db(db_name=TEST_DB_NAME):
    from src.core.config import settings    

    # isolation_level needs to be specified to create a db
    engine = create_engine(settings.db_conn_url, isolation_level='AUTOCOMMIT')
    try:
        with engine.connect() as connection:
            exists = check_if_db_exists(db_name, connection)
            if not exists: 
                create_test_db(db_name, connection)

        yield f"postgresql+psycopg://postgres:postgres@localhost:5432/{db_name}"

    finally:
        with engine.connect() as connection:
            drop_test_db(db_name, connection)


# TODO: Consider writing a contextmanager class that would create and drop the db?
def check_if_db_exists(db_name: str, connection: Connection) -> bool:
    query = text(f"SELECT 1 FROM pg_database WHERE datname='{db_name}'")
    return bool(connection.execute(query).first())


def create_test_db(db_name: str, connection: Connection) -> None:
    connection.execute(text(f"CREATE DATABASE {db_name}"))
    connection.execute(text(f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO postgres;"))


def drop_test_db(db_name: str, connection: Connection) -> None:
    connection.execute(text(f"DROP DATABASE {db_name}"))
