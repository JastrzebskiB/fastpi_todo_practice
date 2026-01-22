from fastapi import Depends
from fastapi.params import Depends as DependsType

from ..auth.services import OrganizationService, UserService
from ..core import settings
from ..core.exceptions import ValidationException
from .dto import (
    BoardResponse,
    BoardResponseFlat,
    CreateBoardPayload,
)
from .models import Board
from .repositories import BoardRepository


class BoardService:
    def __init__(self, repository: BoardRepository = Depends(BoardRepository)) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    def create_board(
        self, 
        payload: CreateBoardPayload, 
        token: str, 
        user_service: UserService,
        organization_service: OrganizationService,
    ) -> BoardResponseFlat:
        me = user_service.get_current_user(token)
        organization_service.validate_user_id_belongs_to_organization(
            payload.organization_id, str(me.id)
        )
        self.validate_board_name_unique_in_organization(payload)
        board = self.repository.create(self.create_domain_board_instance(payload))

        return self.create_board_response_flat(board)

    # Domain object manipulation
    def create_domain_board_instance(self, payload: CreateBoardPayload) -> Board:
        return Board(name=payload.name, organization_id=payload.organization_id)

    # Validation
    def validate_board_name_unique_in_organization(self, payload: CreateBoardPayload) -> None:
        if not self.repository.check_name_unique_in_organization(
            payload.name, str(payload.organization_id)
        ):
            raise ValidationException(f"This organization already has a Board named {payload.name}")

    # Serialization
    def create_board_response_flat(self, board: Board) -> BoardResponseFlat:
        return BoardResponseFlat(id=board.id,name=board.name,organization_id=board.organization_id)
