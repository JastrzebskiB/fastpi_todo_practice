from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uuid import UUID

from .dto import CreateOrganizationPayload, CreateUserPayload
from .exceptions import AuthenticationFailedException
from .models import User
from .services import (
    OrganizationService, 
    UserService, 
    get_organization_service,
    get_user_service,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Technically a view I suppose?
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


@router.get("/me")
async def user_me(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(UserService),
):
    return user_service.get_current_user(token)


# TODO: Start here, add JWT support
# Add endpoint for requesting organization access to DB (you'll need another model there)
@router.post("/token")
async def sign_in(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_service: UserService = Depends(UserService),
): 
    # form_data.username even though the email is expected, this is fine for now
    return user_service.sign_user_in(form_data.username, form_data.password)


@router.post("/users", tags=["users"])
async def user_create(
    payload: CreateUserPayload, 
    service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService),
):
    return service.create_user(payload, organization_service)


@router.post("/organizations", tags=["organizations"])
async def organization_create(
    payload: CreateOrganizationPayload,
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return service.create_organization(payload, user_service)


# TODO: do this after adding auth
# @router.post("/organizations/{organization_id}")
# async def organization_request_access(organization_id: UUID):


@router.get("/organizations", tags=["organizations"])
async def organization_list(
    token: str = Depends(oauth2_scheme),
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService)
):
    return service.get_all(user_service)
