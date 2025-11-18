from alembic import command, config
from pytest import fixture
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from src.auth.models import Organization, User
from src.auth.repositories import OrganizationRepository, UserRepository


TEST_DB_NAME = "fastapi_todo_test"


@fixture(scope="module")
def test_db(db_name=TEST_DB_NAME) -> str:
    from src.core.config import settings    
    
    test_db_url = f"postgresql+psycopg://postgres:postgres@localhost:5432/{db_name}"

    # isolation_level needs to be specified to create a db
    engine = create_engine(settings.db_conn_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            exists = check_if_db_exists(db_name, connection)
            if not exists: 
                create_test_db(db_name, connection)
                run_migrations(test_db_url)

        yield test_db_url

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
    # Kill other connections to the test db first - one remains after (I think)
    # alembic finishes running the migrations?
    drop_other_connections_query = text(
        f"""SELECT 
            pg_terminate_backend(pid) 
        FROM 
            pg_stat_activity 
        WHERE 
            -- don't kill my own connection!
            pid <> pg_backend_pid()
            -- don't kill the connections to other databases
            AND datname = '{db_name}'
        ;"""
    )
    connection.execute(drop_other_connections_query)
    # And finally drop the test db
    connection.execute(text(f"DROP DATABASE {db_name}"))


def run_migrations(db_name: str) -> None:
    alembic_config = config.Config()
    alembic_config.set_main_option("script_location", "%(here)s/alembic")
    alembic_config.set_main_option("sqlalchemy.url", db_name)
    command.upgrade(alembic_config, "head")


def truncate_user_table(sessionmaker):
    with sessionmaker() as session:
        session.execute(text("TRUNCATE TABLE public.user RESTART IDENTITY CASCADE"))
        session.commit()


def truncate_organization_table(sessionmaker):
    with sessionmaker() as session:
        session.execute(text("TRUNCATE TABLE organization RESTART IDENTITY CASCADE"))
        session.commit()


# TODO: Consider changing name to TestSessionmaker?
@fixture(scope="function")
def TestSession(test_db: str) -> sessionmaker:
    engine = create_engine(test_db)
    Session = sessionmaker(engine)

    yield Session
    # No teardown required


@fixture(scope="function")
def test_user_repository(TestSession) -> UserRepository:
    yield UserRepository(TestSession)

    truncate_user_table(TestSession)
    truncate_organization_table(TestSession)


@fixture(scope="function")
def test_organization_repository(TestSession) -> OrganizationRepository:
    yield OrganizationRepository(TestSession)

    truncate_user_table(TestSession)
    truncate_organization_table(TestSession)


# TODO: Consider using partials here?
def create_test_user(
    TestSession: sessionmaker,
    username: str,
    email: str,
    password_hash: str,
    organization: Organization | None,
    owned_organization: Organization | None,
) -> User:
    user = User(
        username=username, 
        email=email,
        password_hash=password_hash,
        organization=organization, 
        owned_organization=owned_organization,
    )
    with TestSession() as session:
        session.add(user)
        session.commit()
        session.refresh(user)

    return user


@fixture(scope="function")
def test_user(
    TestSession: sessionmaker,
    username: str = "test_user",
    password_hash: str = "not_a_hash",
    email: str = "test_user@test.com",
    organization: Organization | None = None,
    owned_organization: Organization | None = None
) -> User:
    yield create_test_user(
        TestSession, 
        username, 
        email, 
        password_hash, 
        organization, 
        owned_organization,
    )

    # Note: cleanup only happens in test_user_repository


@fixture(scope="function")
def test_users(
    TestSession: sessionmaker,
    usernames: list[str] = ["test_1", "test_2"],
    emails: list[str] = ["test_1@test.com", "test_2@test.com"],
    password_hashes: list[str] = ["not_a_hash", "not_a_hash_either"],
    organizations: list[Organization] = [None, None],
    owned_organizations: list[Organization] = [None, None],
) -> list[User]:
    user_data_all = zip(usernames, emails, password_hashes, organizations, owned_organizations)
    yield [
        create_test_user(
            TestSession, data[0], data[1], data[2], data[3], data[4]
        ) for data in user_data_all
    ]

    # Note: cleanup only happens in test_user_repository


# TODO: Consider using partials here?
def create_test_organization(
    TestSession: sessionmaker, 
    name: str, 
    owner_id: str | None = None,
) -> Organization:
    if not owner_id:
        owner = User(username="owner", email="owner@test.com", password_hash="not_a_hash")
    organization = Organization(name="test_org", owner=owner, members=[owner])
    with TestSession() as session:
        session.add(owner)
        session.add(organization)
        session.commit()
        session.refresh(organization)

    return organization


@fixture(scope="function")
def test_organization(
    TestSession: sessionmaker, 
    name: str = "test_org", 
    owner_id: str | None = None,
):
    yield create_test_organization(TestSession, name)

    # Note: cleanup only happens in test_user_repository
