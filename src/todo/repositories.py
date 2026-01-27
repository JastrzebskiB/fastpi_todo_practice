from sqlalchemy.orm import joinedload
from sqlalchemy.orm.session import Session as SessionType
from sqlalchemy.sql import delete, exists, or_, select, update

from ..core import BaseRepository, Session, settings, exceptions
from .models import Board, Column, Task


class BoardRepository(BaseRepository):
    model = Board

    def get_columns_for_board_id(self, board_id: str, user_id: str) -> list[Column]:
        with self.sessionmaker() as session:
            board = self.session_get_board_by_id(session, board_id, with_members=True)
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

    def check_user_id_owns_board_id(self, user_id: str, board_id: str) -> bool:
        with self.sessionmaker() as session:
            board = self.session_get_board_by_id(session, board_id)
            return user_id == str(board.organization.owner_id)

    def check_user_id_has_access_to_board_id(self, user_id: str, board_id: str) -> bool:
        with self.sessionmaker() as session:
            board = self.session_get_board_by_id(session, board_id)
            return user_id == str(board.organization.owner_id)

    def list_boards_for_organization(self, organization_id: str) -> list[Board]:
        with self.sessionmaker() as session:
            return session.scalars(
                select(self.model).where(self.model.organization_id == organization_id)
            ).all()

    def get_board_by_id_as_user(self, board_id: str, user_id: str) -> Board:
        with self.sessionmaker() as session:
            board = self.session_get_board_by_id(session, board_id, with_members=True)
            if not user_id in [str(member.id) for member in board.organization.members]:
                raise exceptions.AuthorizationFailedException
        return board

    def session_get_board_by_id(
        self, 
        session: SessionType, 
        board_id: str, 
        with_members: bool = False,
    ) -> Board:
        from src.auth.models import Organization

        options = [joinedload(self.model.columns).joinedload(Column.tasks)]
        if with_members:
            options.append(joinedload(self.model.organization).joinedload(Organization.members))
        else:
            options.append(joinedload(self.model.organization))

        board = session.scalar(
            select(self.model).options(*options).where(self.model.id == board_id)
        )
        if not board:
            raise exceptions.BoardNotFound
        return board

    def delete_board(self, board_id: str, user_id: str) -> tuple[str, bool]:
        with self.sessionmaker() as session:
            board = self.session_get_board_by_id(session, board_id)

            if not user_id == str(board.organization.owner_id):
                raise exceptions.AuthorizationFailedException

            existing_tasks = []
            for column in board.columns:
                if not column.is_terminal:
                    existing_tasks.extend(column.tasks)
            if existing_tasks:
                return "Cannot delete a board that has unfinished tasks", False
            
            for column in board.columns:
                for task in column.tasks:
                    session.delete(task)
                session.delete(column)
            session.delete(board)
            session.commit()
        return "Board deleted successfully", True


class ColumnRepository(BaseRepository):
    model = Column

    def check_name_unique_in_board(self, name: str, board_id: str) -> bool:
        return not self.check_name_exists_in_board(name, board_id)
    
    def check_name_exists_in_board(self, name: str, board_id: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(
                exists()
                .where(self.model.board_id == board_id, self.model.name == name)
                .select()
            )

    def partial_update_column(
        self, 
        column_id: str,
        user_id: str,
        name: str | None,
        order: int | None,
        is_terminal: bool | None,
    ) -> Column:
        with self.sessionmaker() as session:
            column = self.session_get_column_by_id_for_owner(session, column_id, user_id)

            if name is not None:
                column.name = name
            if order is not None:
                column.order = order
            if is_terminal is not None:
                column.is_terminal = is_terminal

            session.add(column)
            session.commit()
            session.refresh(column)
        
        return column

    def delete_column(self, column_id: str, user_id: str) -> tuple[str, bool]:
        with self.sessionmaker() as session:
            column = self.session_get_column_by_id_for_owner(
                session, column_id, user_id, with_tasks=True
            )
            
            if not column.is_terminal and column.tasks:
                return "Cannot delete a column that is not terminal and has tasks", False
            elif column.is_terminal and column.tasks:
                for task in column.tasks:
                    session.delete(task)
            session.delete(column)
            session.commit()

        return "Column deleted successfully", True

    def session_get_column_by_id_for_owner(
        self, 
        session: SessionType,
        column_id: str, 
        user_id: str,
        with_tasks: bool = False
    ) -> Column:
        # TODO: wait, instead of checking if user can make the changes like this maybe 
        # I could do a joined query and use the user_id as a part of it?
        options = [joinedload(self.model.board).joinedload(Board.organization)]
        if with_tasks:
            options.append(joinedload(self.model.tasks))

        column = session.scalar(
            select(self.model).options(*options).where(self.model.id == column_id)
        )

        if not column:
            raise exception.ColumnNotFound

        if not user_id == str(column.board.organization.owner_id):
            raise exceptions.AuthorizationFailedException
        
        return column


class TaskRepository(BaseRepository):
    model = Task
