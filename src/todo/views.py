from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse

from ..auth.services import UserService, OrganizationService
from ..core.auth import oauth2_scheme
from .dto import CreateBoardPayload, CreateColumnPayload, PartialUpdateColumnPayload
from .services import BoardService, ColumnService, TaskService

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
    return service.create_board(payload, token, column_service, user_service, organization_service)


@router.get("/organizations/{organization_id}/boards", tags=["boards"])
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


@router.get("/board/{board_id}", tags=["boards"])
async def board_details(
    board_id: str,
    token: str = Depends(oauth2_scheme),
    service: BoardService = Depends(BoardService),
    column_service: ColumnService = Depends(ColumnService),
    task_service: TaskService = Depends(TaskService),
    user_service: UserService = Depends(UserService),
):
    return service.get_board_by_id(
        board_id, token, column_service, task_service, user_service,
    )


@router.delete("/board/{board_id}", tags=["boards"])
async def board_delete(
    board_id: str,
    token: str = Depends(oauth2_scheme),
    service: BoardService = Depends(BoardService),
    user_service: UserService = Depends(UserService),
):
    message, deleted = service.delete_board(board_id, token, user_service)
    status_code = status.HTTP_200_OK if deleted else status.HTTP_422_UNPROCESSABLE_CONTENT
    return JSONResponse(status_code=status_code, content={"detail": message})


# Columns
@router.post("/board/{board_id}/columns", tags=["columns"])
async def column_create(
    payload: CreateColumnPayload,
    board_id: str,
    token: str = Depends(oauth2_scheme),
    service: ColumnService = Depends(ColumnService),
    board_service: BoardService = Depends(BoardService),
    user_service: UserService = Depends(UserService),
):
    return service.create_column(payload, board_id, token, board_service, user_service)


@router.patch("/column/{column_id}", tags=["columns"])
async def column_partial_update(
    payload: PartialUpdateColumnPayload,
    column_id: str,
    token: str = Depends(oauth2_scheme),
    service: ColumnService = Depends(ColumnService),
    user_service: UserService = Depends(UserService),
):
    return service.partial_update_column(payload, column_id, token, user_service)
