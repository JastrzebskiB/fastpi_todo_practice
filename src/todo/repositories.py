from sqlalchemy.orm import joinedload
from sqlalchemy.orm.session import Session as SessionType
from sqlalchemy.sql import delete, exists, or_, select, update

from ..core import BaseRepository, Session, settings, exceptions
from .models import Board, Column, Task


class BoardRepository(BaseRepository):
    model = Board

    def get_columns_for_board_id(self, board_id: str, user_id: str) -> list[Column]:
        from src.auth.models import Organization

        with self.sessionmaker() as session:
            board = session.scalar(
                select(self.model)
                .options(
                    joinedload(self.model.columns),
                    joinedload(self.model.organization).joinedload(Organization.members),
                )
                .where(self.model.id == board_id)
            )
            if not user_id in [str(member.id) for member in board.organization.members]:
                raise exceptions.AuthorizationFailedException
        
        return board.columns

    def check_name_unique_in_organization(self, name: str, organization_id: str) -> bool:
        return not self.check_name_exists_in_organization(name, organization_id)

    def check_name_exists_in_organization(self, name: str, organization_id: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(
                exists().where(
                    self.model.name == name, 
                    self.model.organization_id == organization_id,
                ).select()
            )

    def list_boards_for_organization(self, organization_id: str) -> list[Board]:
        with self.sessionmaker() as session:
            return session.scalars(
                select(self.model).where(self.model.organization_id == organization_id)
            ).all()

    def get_board_by_id_as_user(self, board_id: str, user_id: str) -> Board:
        from src.auth.models import Organization

        with self.sessionmaker() as session:
            board = session.scalar(
                select(self.model)
                .options(
                    joinedload(self.model.columns).joinedload(Column.tasks),
                    joinedload(self.model.organization).joinedload(Organization.members),
                )
                .where(self.model.id == board_id)
            )
            if not user_id in [str(member.id) for member in board.organization.members]:
                raise exceptions.AuthorizationFailedException
        
        return board


class ColumnRepository(BaseRepository):
    model = Column


class TaskRepository(BaseRepository):
    model = Task
