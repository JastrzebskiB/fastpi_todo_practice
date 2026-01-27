from fastapi import Depends
from fastapi.params import Depends as DependsType

from ..auth.services import OrganizationService, UserService
from ..core import settings
from ..core.exceptions import AuthorizationFailedException, ValidationException
from .constants import DEFAULT_COLUMNS
from .dto import (
    BoardResponse,
    BoardResponseFlat,
    BoardResponseFullDetails,
    CreateBoardPayload,
    CreateColumnPayload,
    ColumnResponseFlat,
    ColumnResponse,
    PartialUpdateColumnPayload,
    TaskResponseFlat,
)
from .models import Board, Column, Task
from .repositories import BoardRepository, ColumnRepository, TaskRepository


class BoardService:
    def __init__(self, repository: BoardRepository = Depends(BoardRepository)) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    def create_board(
        self, 
        payload: CreateBoardPayload, 
        token: str, 
        column_service: "ColumnService",
        user_service: UserService,
        organization_service: OrganizationService,
    ) -> BoardResponseFlat:
        me_id = str(user_service.get_current_user(token).id)
        # TODO: Only org owner should be able to create a board
        organization_service.validate_user_id_belongs_to_organization(
            payload.organization_id, me_id
        )
        self.validate_board_name_unique_in_organization(payload)
        board = self.repository.create(self.create_domain_board_instance(payload))
        columns = self.create_columns_for_new_board(str(board.id), me_id, payload, column_service)

        return self.create_board_response(board, columns)

    def create_columns_for_new_board(
        self, 
        board_id: str, 
        user_id: str,
        payload: CreateBoardPayload, 
        column_service: "ColumnService",
    ) -> list[ColumnResponseFlat]:
        if payload.use_columns_from_board_id:
            columns_to_copy = self.repository.get_columns_for_board_id(
                payload.use_columns_from_board_id, user_id
            )
            column_data = [
                CreateColumnPayload(
                    name=column.name, order=column.order, is_terminal=column.is_terminal
                ) 
                for column in columns_to_copy
            ]
            columns = column_service.create_columns_for_board_id(board_id, column_data)
        elif payload.add_default_columns:
            columns = column_service.create_columns_for_board_id(board_id, DEFAULT_COLUMNS)
        else:
            columns = []
        
        return [column_service.create_column_response_flat(column) for column in columns]

    def list_boards_for_organization(
        self,
        organization_id: str,
        token: str,
        user_service: UserService,
        organization_service: OrganizationService,
    ) -> list[BoardResponseFlat]:
        me = user_service.get_current_user(token)
        organization_service.validate_user_id_belongs_to_organization(organization_id, str(me.id))
        
        return [
            self.create_board_response_flat(board) 
            for board in self.repository.list_boards_for_organization(organization_id)
        ]

    def get_board_by_id(
        self,
        board_id: str,
        token: str,
        column_service: "ColumnService",
        task_service: "TaskService",
        user_service: UserService,
    ) -> BoardResponseFullDetails:
        my_id = str(user_service.get_current_user(token).id)
        board = self.repository.get_board_by_id_as_user(board_id, my_id)
        # TODO: I don't like the inconsistency: in create_board_response we pass the list of columns
        # but in create_column_response_full we pass task_service instead...
        columns = [
            column_service.create_column_response(column, task_service) for column in board.columns
        ]

        return self.create_board_response_full(board, columns)

    def delete_board(
        self, 
        board_id: str, 
        token: str, 
        user_service: UserService,
    ) -> tuple[bool, str]:
        my_id = str(user_service.get_current_user(token).id)
        return self.repository.delete_board(board_id, my_id)

    # Domain object manipulation
    def create_domain_board_instance(self, payload: CreateBoardPayload) -> Board:
        return Board(name=payload.name, organization_id=payload.organization_id)

    # Validation
    def validate_board_name_unique_in_organization(self, payload: CreateBoardPayload) -> None:
        if not self.repository.check_name_unique_in_organization(
            payload.name, str(payload.organization_id)
        ):
            raise ValidationException(f"This organization already has a Board named {payload.name}")

    def validate_user_owns_board(self, user_id: str, board_id: str) -> None:
        if not self.repository.check_user_id_owns_board_id(user_id, board_id):
            raise AuthorizationFailedException

    # Serialization
    def create_board_response_flat(self, board: Board) -> BoardResponseFlat:
        return BoardResponseFlat(id=board.id,name=board.name,organization_id=board.organization_id)

    def create_board_response(
        self, 
        board: Board, 
        columns: list[ColumnResponseFlat],
    ) -> BoardResponse:
        return BoardResponse(
            id=board.id,
            organization_id=board.organization_id,
            name=board.name,
            columns=columns,
        )

    # TODO: We can probably just make the columns be either of the column types and use flat/regular
    # dtos for Board
    def create_board_response_full(
        self, 
        board: Board, 
        columns: list[ColumnResponse],
    ) -> BoardResponseFullDetails:
        return BoardResponseFullDetails(
            id=board.id,
            organization_id=board.organization_id,
            name=board.name,
            columns=columns,
        )


class ColumnService:
    def __init__(self, repository: ColumnRepository = Depends(ColumnRepository)) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    def create_column(
        self, 
        payload: CreateBoardPayload, 
        board_id: str, 
        token: str, 
        board_service: BoardService,
        user_service: UserService,
    ) -> ColumnResponseFlat:
        my_id = str(user_service.get_current_user(token).id)
        board_service.validate_user_owns_board(my_id, board_id)
        self.validate_column_name_unique_in_board(payload.name, board_id)
        return self.create_columns_for_board_id(board_id, [payload])

    def create_columns_for_board_id(
        self, 
        board_id: str, 
        payloads: list[CreateColumnPayload],
    ) -> list[ColumnResponseFlat]:
        columns = [
            self.repository.create(column) 
            for column in self.create_domain_column_instances_for_board_id(board_id, payloads)
        ]
        return [self.create_column_response_flat(column) for column in columns]

    def partial_update_column(
        self, 
        payload: PartialUpdateColumnPayload,
        column_id: str,
        token: str,
        user_service: UserService
    ) -> ColumnResponseFlat:
        my_id = str(user_service.get_current_user(token).id)
        return self.create_column_response_flat(
            self.repository.partial_update_column(
                column_id=column_id, 
                user_id=my_id,
                name=payload.name, 
                order=payload.order,
                is_terminal=payload.is_terminal,
            )
        )

    def delete_column(
        self,
        column_id: str,
        token: str,
        user_service: UserService,
    ) -> tuple[str, bool]:
        my_id = str(user_service.get_current_user(token).id)
        return self.repository.delete_column(column_id, my_id)

    # Domain object manipulation
    def create_domain_column_instances_for_board_id(
        self, 
        board_id: str, 
        payloads: list[CreateColumnPayload],
    ) -> list[Column]:
        return [
            self.create_domain_column_instance(board_id, payload) for payload in payloads
        ]

    def create_domain_column_instance(self, board_id: str, payload: CreateColumnPayload) -> Column:
        return Column(
            name=payload.name, 
            order=payload.order, 
            board_id=board_id, 
            is_terminal=payload.is_terminal,
        )

    # Validation
    def validate_column_name_unique_in_board(self, name: str, board_id: str) -> None:
        if not self.repository.check_name_unique_in_board(name, board_id):
            raise ValidationException(f"Column named {name} already exists for this board")

    # Serialization
    def create_column_response_flat(self, column: Column) -> ColumnResponseFlat:
        return ColumnResponseFlat(
            id=column.id,
            board_id=column.board_id,
            name=column.name,
            order=column.order,
            is_terminal=column.is_terminal,
        )
    
    def create_column_response(
        self, 
        column: Column, 
        task_service: "TaskService",
    ) -> ColumnResponse:
        return ColumnResponse(
            id=column.id,
            board_id=column.board_id,
            name=column.name,
            order=column.order,
            is_terminal=column.is_terminal,
            tasks=[task_service.create_task_response_flat(task) for task in column.tasks],
        )


class TaskService:
    def __init__(self, repository: TaskRepository = Depends(TaskRepository)) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    # Serialization
    def create_task_response_flat(self, task: Task) -> TaskResponseFlat:
        return TaskResponseFlat(
            id=task.id,
            column_id=task.column_id,
            assigned_to=task.assigned_to,
            name=task.name,
            order=task.order,
        )
