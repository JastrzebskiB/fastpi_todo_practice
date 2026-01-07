from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uuid import UUID

from .dto import (
    OrganizationAccessRequestDecisionPayload,
    CreateOrganizationPayload, 
    CreateUserPayload,
)
from .models import User
from .services import (
    OrganizationAccessRequestService,
    OrganizationService, 
    UserService,
)

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


@router.post("/token")
async def sign_in(
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_service: UserService = Depends(UserService),
): 
    # form_data.username even though the email is expected as content, this is intentional
    return user_service.sign_user_in(form_data)


@router.post("/users", tags=["users"])
async def user_create(payload: CreateUserPayload, service: UserService = Depends(UserService)):
    return service.create_user(payload)

# ===== LINE ABOVE WHICH WORK IS DONE =====

@router.get("/me")
async def user_current(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(UserService),
):
    return user_service.get_current_user(token, check_user_exists=True)

# ===== LINE ABOVE WHICH WIP =====

@router.get("/me/organizations")
async def organizations_mine(
    token: str = Depends(oauth2_scheme), 
    service: OrganizationService = Depends(OrganizationService),
):
    return service.get_owned_organizations(token)


@router.post("/organizations", tags=["organizations"])
async def organization_create(
    payload: CreateOrganizationPayload,
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return service.create_organization(payload, user_service)


@router.get("/organizations", tags=["organizations"])
async def organization_list(
    token: str = Depends(oauth2_scheme),
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService)
):
    return service.get_all(user_service)


@router.get(
    "/me/organization/{organization_id}/access_requests", tags=["organization_access_requests"]
)
async def organization_mine_access_requests(
    organization_id: str,
    token: str = Depends(oauth2_scheme),
    service: OrganizationAccessRequestService = Depends(OrganizationAccessRequestService),
    user_service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService),
):
    return service.get_pending_requests_for_organization(
        organization_id,
        token,
        user_service,
        organization_service
    )


@router.post(
    "/organization/{organization_id}/access_requests/", tags=["organization_access_requests"]
)
async def organization_request_access_create(
    organization_id: str,
    token: str = Depends(oauth2_scheme),
    service: OrganizationAccessRequestService = Depends(OrganizationAccessRequestService),
    user_service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService),
):
    return service.create_organization_access_request(
        organization_id, token, user_service, organization_service
    )


@router.post(
    "/organization_access_requests/{organization_access_request_id}", 
    tags=["organization_access_requests"]
)
async def organization_access_request_process(
    organization_access_request_id: str,
    payload: OrganizationAccessRequestDecisionPayload,
    token: str = Depends(oauth2_scheme),
    service: OrganizationAccessRequestService = Depends(OrganizationAccessRequestService),
    user_service: UserService = Depends(UserService),
    organization_service: OrganizationService = Depends(OrganizationService),
):
    return service.process_organization_access_request(
        organization_access_request_id, payload, token, user_service, organization_service,
    )
