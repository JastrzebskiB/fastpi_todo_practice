from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from ..auth.services import UserService, OrganizationService
from ..core.auth import oauth2_scheme
from .dto import CreateBoardPayload
from .services import BoardService, ColumnService

router = APIRouter(prefix="/todo", tags=["todo"])


# Boards
@router.post("/board", tags=["boards"])
async def board_create(
    payload: CreateBoardPayload,
    token: str = Depends(oauth2_scheme),
    service: BoardService = Depends(BoardService),
    column_service: ColumnService = Depends(ColumnService),
    user_service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService)
):
    # TODO: Also create default columns
    return service.create_board(payload, token, column_service, user_service, organization_service)


@router.get("/organizations/{organization_id}/boards")
async def boards_for_organization_list(
    organization_id: str,
    token: str = Depends(oauth2_scheme),
    service: BoardService = Depends(BoardService),
    user_service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService),
):
    return service.list_boards_for_organization(
        organization_id, token, user_service, organization_service,
    )
