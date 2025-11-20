from fastapi import APIRouter, Depends

from .dto import CreateOrganizationPayload, CreateUserPayload 
from .models import User
from .services import (
    OrganizationService, 
    UserService, 
    get_organization_service,
    get_user_service,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/users", tags=["users"])
async def user_create(
    payload: CreateUserPayload, 
    service: UserService = Depends(get_user_service),
):
    return service.create_user(payload)


@router.post("/organizations", tags=["organizations"])
async def organization_create(
    payload: CreateOrganizationPayload,
    service: OrganizationService = Depends(get_organization_service),
    user_service: UserService = Depends(get_user_service)
):
    return service.create_organization(payload, user_service)
