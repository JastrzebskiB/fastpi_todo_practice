from fastapi import APIRouter

from .dto import CreateUserPayload
from .models import User
from .services import create_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/users", tags=["users"])
async def user_post(payload: CreateUserPayload):
    return create_user(payload)
