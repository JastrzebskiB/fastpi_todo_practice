from datetime import datetime

from alembic import command, config
from pytest import fixture
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from src.auth.models import OrganizationAccessRequest, Organization, User
from src.auth.repositories import (
    OrganizationAccessRequestRepository, 
    OrganizationRepository, 
    UserRepository,
)
from src.auth.services import OrganizationAccessRequestService, OrganizationService, UserService
from src.todo.models import Board
from src.todo.repositories import BoardRepository
from src.todo.services import BoardService


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


# TODO: Consider changing name to TestSessionmaker?
@fixture(scope="function")
def TestSession(test_db: str) -> sessionmaker:
    engine = create_engine(test_db)
    Session = sessionmaker(engine)

    yield Session
    # No teardown required


# auth
def truncate_user_table(sessionmaker):
    with sessionmaker() as session:
        session.execute(text("TRUNCATE TABLE public.user RESTART IDENTITY CASCADE"))
        session.commit()


def truncate_organization_table(sessionmaker):
    with sessionmaker() as session:
        session.execute(text("TRUNCATE TABLE organization RESTART IDENTITY CASCADE"))
        session.commit()


def truncate_organization_access_request_table(sessionmaker):
    with sessionmaker() as session:
        session.execute(text("TRUNCATE TABLE organization_access_request RESTART IDENTITY CASCADE"))
        session.commit()


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


@fixture(scope="function")
def test_organization_access_request_repository(
    TestSession
) -> OrganizationAccessRequestRepository:
    yield OrganizationAccessRequestRepository(TestSession)

    truncate_organization_access_request_table(TestSession)
    truncate_user_table(TestSession)
    truncate_organization_table(TestSession)


@fixture(scope="function")
def test_user_service(test_user_repository) -> UserService:
    yield UserService(repository=test_user_repository)

    # Cleanup done in test_user_repository


@fixture(scope="function")
def test_organization_service(test_organization_repository) -> OrganizationService:
    organization_service = OrganizationService()
    organization_service.repository = test_organization_repository
    yield organization_service

    # Cleanup done in test_organization_repository


@fixture(scope="function")
def test_organization_access_request_service(
    test_organization_access_request_repository
) -> OrganizationAccessRequestService:
    organization_access_request_service = OrganizationAccessRequestService()
    organization_access_request_service.repository = test_organization_access_request_repository
    yield organization_access_request_service

    # Cleanup done in test_organization_repository


def create_test_user(
    TestSession: sessionmaker,
    username: str,
    email: str,
    password_hash: str,
    organizations: list[Organization],
    owned_organization: Organization | None,
) -> User:
    user = User(
        username=username, 
        email=email,
        password_hash=password_hash,
        owned_organization=owned_organization,
    )
    for organization in organizations:
        organization.members.append(user)
    with TestSession() as session:
        session.add(user)
        [session.add(organization) for organization in organizations]
        session.commit()
        session.refresh(user)

    return user


@fixture(scope="function")
def test_user(
    TestSession: sessionmaker,
    username: str = "test_user",
    email: str = "test_user@test.com",
    # Unhashed password is "pass"
    password_hash: str = "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1",
    organizations: list[Organization] | None = None,
    owned_organization: Organization | None = None
) -> User:
    if organizations is None:
        organizations = []
    yield create_test_user(
        TestSession, 
        username, 
        email, 
        password_hash, 
        organizations, 
        owned_organization,
    )

    # Note: cleanup only happens in test_user_repository


@fixture(scope="function")
def test_users(
    TestSession: sessionmaker,
    usernames: list[str] = ["test_1", "test_2"],
    emails: list[str] = ["test_1@test.com", "test_2@test.com"],
    # Unhashed password is "pass"
    password_hashes: list[str] = [
        "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1", 
        "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1",
    ],
    organizations: list[list[Organization]] = [[], []],
    owned_organizations: list[Organization] = [None, None],
) -> list[User]:
    user_data_all = zip(usernames, emails, password_hashes, organizations, owned_organizations)
    yield [
        create_test_user(
            TestSession, data[0], data[1], data[2], data[3], data[4]
        ) for data in user_data_all
    ]

    # Note: cleanup only happens in test_user_repository


def create_test_organization(
    TestSession: sessionmaker, 
    name: str, 
    owner: User | None = None,
    members: list[User] | None = None
) -> Organization:
    if not owner:
        owner = User(username="owner", email="owner@test.com", password_hash="not_a_hash")
    if not members:
        members = [owner]
    else:
        members = [owner, *members]

    organization = Organization(name=name, owner=owner, members=members)
    with TestSession() as session:
        session.add(owner)
        session.add(organization)
        session.commit()
        session.refresh(organization, attribute_names=["owner", "members"])

    return organization


@fixture(scope="function")
def test_organization(
    TestSession: sessionmaker, 
    name: str = "test_org", 
):
    yield create_test_organization(TestSession, name)

    # Note: cleanup only happens in test_user_repository


@fixture(scope="function")
def test_organization_with_members(
    TestSession: sessionmaker, 
    test_users: list[User],
    name: str = "test_org", 
):
    yield create_test_organization(TestSession, name, members=test_users)

    # Note: cleanup only happens in test_user_repository


def create_test_organization_access_request(
    TestSession: sessionmaker, 
    requester_id: str,
    organization_id: str,
    approved: bool | None = None,
    updated_at: datetime | None = None,
) -> OrganizationAccessRequest:
    access_request = OrganizationAccessRequest(
        requester_id=requester_id, 
        organization_id=organization_id, 
        approved=approved,
        updated_at=updated_at,
    )
    with TestSession() as session:
        session.add(access_request)
        session.commit()
        session.refresh(access_request)

    return access_request


# todo
def truncate_board_table(sessionmaker):
    with sessionmaker() as session:
        session.execute(text("TRUNCATE TABLE board RESTART IDENTITY CASCADE"))
        session.commit()


@fixture(scope="function")
def test_board_repository(TestSession) -> BoardRepository:
    yield BoardRepository(TestSession)

    truncate_board_table(TestSession)


@fixture(scope="function")
def test_board_service(test_board_repository) -> BoardService:
    yield BoardService(repository=test_board_repository)

    # Cleanup done in test_board_repository


def create_test_board(
    TestSession: sessionmaker, 
    name: str, 
    organization_id: str,
) -> Board:
    with TestSession() as session:
        board = Board(name=name, organization_id=organization_id)
        session.add(board)
        session.commit()
        session.refresh(board)

    return board
