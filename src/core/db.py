from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import (
    DeclarativeBase, 
    Mapped, 
    mapped_column, 
    sessionmaker,
)
from sqlalchemy.sql import exists, func

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

    def create(self, model_instance: Base, attribute_names: list[str] | None = None) -> Base:
        # Assumes data from model_data has already been validated
        with self.sessionmaker() as session:
            try:
                session.add(model_instance)
                session.commit()
                session.refresh(model_instance, attribute_names=attribute_names)
            except Exception as e:  # Intentional catch-all - we want a rollback for ALL exceptions
                session.rollback()
                raise e
        return model_instance

    # TODO: needs test
    def exists_with_id(
        self, 
        id: str,  # UUID4
    ) -> bool:
        with self.sessionmaker() as session:
            session.scalar(exists().where(self.model.id == id).select())

    def get_all(self) -> list[Base]:
        with self.sessionmaker() as session:
            return session.query(self.model).all()

    def get_count(self) -> int:
        with self.sessionmaker() as session:
            return session.query(self.model).count()

    # TODO: needs test
    def get_by_id(
        self, 
        id: str,  # UUID4
    ) -> Base:
        with self.sessionmaker() as session:
            return session.query(self.model).get(id)

    # TODO: needs test
    def get_all_by_id(
        self, 
        ids: list[str],  # list[UUID4]
    ) -> list[Base]:
        with self.sessionmaker() as session:
            return session.query(self.model).filter(self.model.id.in_(ids)).all()
