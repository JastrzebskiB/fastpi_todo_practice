from fastapi import APIRouter, Depends

from .dto import CreateUserPayload
from .models import User
from .services import CreateUserService, get_create_user_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/users", tags=["users"])
async def user_post(
    payload: CreateUserPayload, 
    service: CreateUserService = Depends(get_create_user_service),
):
    return service.create_user(payload)
