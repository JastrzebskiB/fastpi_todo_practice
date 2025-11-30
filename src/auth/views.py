from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordBearer
from uuid import UUID

from .dto import CreateOrganizationPayload, CreateUserPayload 
from .models import User
from .services import (
    OrganizationService, 
    UserService, 
    get_organization_service,
    get_user_service,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Technicall a view I suppose
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


# TODO: writing auth in progress
# @router.post("/token")
# async def sign_in_oauth(payload: SignInPayload, service: UserService = Depends(get_user_service)):
#     ...

@router.post("/users", tags=["users"])
async def user_create(
    payload: CreateUserPayload, 
    service: UserService = Depends(get_user_service),
    organization_service: OrganizationService = Depends(get_organization_service),
):
    return service.create_user(payload, organization_service)


@router.post("/organizations", tags=["organizations"])
async def organization_create(
    payload: CreateOrganizationPayload,
    service: OrganizationService = Depends(get_organization_service),
    user_service: UserService = Depends(get_user_service)
):
    return service.create_organization(payload, user_service)


# TODO: do this after adding auth
# @router.post("/organizations/{organization_id}")
# async def organization_request_access(organization_id: UUID):


@router.get("/organizations", tags=["organizations"])
async def organization_list(
    # token = Depends(oauth2_scheme),  # TODO: writing auth in progress
    service: OrganizationService = Depends(get_organization_service),
    user_service: UserService = Depends(get_user_service)
):
    return service.get_all(user_service)
