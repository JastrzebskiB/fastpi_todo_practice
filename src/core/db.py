from datetime import datetime
from typing import Union
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import (
    DeclarativeBase, 
    Mapped,
    Query,
    Relationship,
    joinedload,
    lazyload,
    mapped_column,
    selectinload, 
    sessionmaker,
    subqueryload,
)
from sqlalchemy.sql import exists, func

from .config import settings

# Type hint alias
LoadStrategy = Union[joinedload, lazyload, subqueryload, selectinload, Relationship]

engine = create_engine(settings.db_conn_url)
Session = sessionmaker(engine)


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

    # TODO: Remove this before "release", it's just added for ease of development
    def get_first(self, order_by_created_at: bool = True) -> Base:
        with self.sessionmaker() as session:
            query = session.query(self.model).order_by(self.model.created_at)
            if order_by_created_at and hasattr(self.model, "created_at"):
                query = query.order_by(self.model.created_at)
            return query.first() 

    def refresh(self, model_instance: Base, attribute_names: list[str] | None = None) -> None:
        with self.sessionmaker() as session:
            session.refresh(model_instance, attribute_names)

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

    # TODO: will probably need attribute_names?
    # TODO: this doesn't work due to objects being outside of session scope when modifying the 
    # fields
    def update(self, model_instance: Base) -> Base:
        with self.sessionmaker() as session:
            try:
                session.add(model_instance)
                session.commit()
            except Exception as e:  # Intentional catch-all - we want a rollback for ALL exceptions
                session.rollback()
                raise e
        return model_instance

    def query_with_options(
        self, 
        query: Query, 
        relationships: list[LoadStrategy] | None = None
    ) -> Query:
        if not relationships:
            return query
        for relationship in relationships:
          query = query.options(relationship)
        return query  

    def exists_with_id(self, id: UUID) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(exists().where(self.model.id == id).select())

    def get_all(self, relationships: list[LoadStrategy] | None = None) -> list[Base]:
        with self.sessionmaker() as session:
            return self.query_with_options(session.query(self.model), relationships).all()

    def get_count(self) -> int:
        with self.sessionmaker() as session:
            return session.query(self.model).count()

    def get_by_id(self, id: UUID, relationships: list[LoadStrategy] | None = None) -> Base:
        with self.sessionmaker() as session:
            return self.query_with_options(session.query(self.model), relationships).get(id)

    def get_all_by_id(self, ids: list[UUID]) -> list[Base]:
        with self.sessionmaker() as session:
            return session.query(self.model).filter(self.model.id.in_(ids)).all()
