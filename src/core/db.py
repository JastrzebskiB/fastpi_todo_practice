from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.sql import func

from .config import settings


class Base(DeclarativeBase):
    ...


class CommonFieldsMixin:
    created_at: Mapped[datetime] = mapped_column(server_default=func.CURRENT_TIMESTAMP())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.CURRENT_TIMESTAMP(), 
        onupdate=func.CURRENT_TIMESTAMP(),
    )


engine = create_engine(settings.db_conn_url)
# TODO: Consider expire_on_commit=False? https://docs.sqlalchemy.org/en/20/errors.html#error-bhk3
Session = sessionmaker(engine)  
