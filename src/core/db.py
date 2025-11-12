from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import (
    DeclarativeBase, 
    Mapped, 
    mapped_column, 
    sessionmaker,
)
from sqlalchemy.sql import func

from .config import settings


engine = create_engine(settings.db_conn_url)
# TODO: Consider expire_on_commit=False? https://docs.sqlalchemy.org/en/20/errors.html#error-bhk3
Session = sessionmaker(engine)


# TODO: Bad class name
class Base(DeclarativeBase):
    ...


class CommonFieldsMixin:
    created_at: Mapped[datetime] = mapped_column(server_default=func.CURRENT_TIMESTAMP())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.CURRENT_TIMESTAMP(), 
        onupdate=func.CURRENT_TIMESTAMP(),
    )


class BaseRepository:
    model = None

    def __init__(self, sessionmaker: sessionmaker = Session):
        if not self.model:
            raise NotImplementedError(
                "Repositories are model specific and should have model as a class variable."
            )
        self.sessionmaker = sessionmaker

    def create(self, model_data: BaseModel) -> Base:
        # Assumes data from model_data has already been validated
        orm_model_instance = self.model(**model_data.model_dump())
        with self.sessionmaker() as session:
            try:
                session.add(orm_model_instance)
                session.commit()
                session.refresh(orm_model_instance)
            except Exception as e:  # Intentional catch-all - we want a rollback for ALL exceptions
                session.rollback()
                raise e
        return orm_model_instance

    def get_all(self) -> list[Base]:
        with self.sessionmaker() as session:
            return session.query(self.model).all()
