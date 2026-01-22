from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from ..auth.services import UserService, OrganizationService
from ..core.auth import oauth2_scheme
from .dto import CreateBoardPayload
from .services import BoardService

router = APIRouter(prefix="/todo", tags=["todo"])


# Boards
@router.post("/board", tags=["boards"])
async def board_create(
    payload: CreateBoardPayload,
    token: str = Depends(oauth2_scheme),
    service: BoardService = Depends(BoardService),
    user_service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService)
):
    return service.create_board(payload, token, user_service, organization_service)
