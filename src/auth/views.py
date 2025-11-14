from fastapi import APIRouter, Depends

from .dto import CreateOrganizationPayload, CreateUserPayload 
from .models import User
from .services import (
    CreateOrganizationService, 
    CreateUserService, 
    get_create_organization_service,
    get_create_user_service,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/users", tags=["users"])
async def user_create(
    payload: CreateUserPayload, 
    service: CreateUserService = Depends(get_create_user_service),
):
    return service.create_user(payload)


@router.post("/organizations", tags=["organizations"])
async def organization_create(
    payload: CreateOrganizationPayload,
    service: CreateOrganizationService = Depends(get_create_organization_service)    
):
    return service.create_organization(payload)
