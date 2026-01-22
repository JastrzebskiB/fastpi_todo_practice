from logging.config import fileConfig

from alembic import context
from alembic.config import Config
from sqlalchemy import create_engine, pool

from src.core.config import settings
from src.core.db import Base
from src.auth.models import Organization, OrganizationAccessRequest, User
from src.todo.models import Board, Column, Task


def use_default_db_url_if_needed(config: Config) -> None:
    # sqlalchemy.url gets set explicitly in the integration tests conftest; if it's not specified,
    # use the db url that's stiched together from values in the .env file.
    # DO NOT set the db url in alembic.ini
    if not config.get_main_option("sqlalchemy.url"):
        config.set_main_option("sqlalchemy.url", settings.db_conn_url)


def run_migrations_offline(config: Config) -> None:#
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online(config: Config) -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    engine = create_engine(config.get_main_option("sqlalchemy.url"), poolclass=pool.NullPool)

    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


# Base model class used for revision autogeneration
target_metadata = Base.metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

use_default_db_url_if_needed(config)

if context.is_offline_mode():
    run_migrations_offline(config)
else:
    run_migrations_online(config)
