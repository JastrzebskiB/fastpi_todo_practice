from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uuid import UUID

from .dto import (
    CreateOrganizationPayload, 
    CreateUserPayload,
    ModifyOrganizationMembershipPayload,
    OrganizationAccessRequestDecisionPayload,
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


# Users
@router.post("/users", tags=["users"])
async def user_create(payload: CreateUserPayload, service: UserService = Depends(UserService)):
    return service.create_user(payload)


@router.get("/me", tags=["users"])
async def user_current(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(UserService),
):
    return user_service.get_current_user(token, check_user_exists=True)


@router.delete("/me", tags=["users"])
async def user_current_delete(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(UserService),
):
    user_service.delete_current_user(token)
    return JSONResponse(content={"detail": "Successfully deleted user"})


# Organizations
@router.post("/organizations", tags=["organizations"])
async def organization_create(
    payload: CreateOrganizationPayload,
    token: str = Depends(oauth2_scheme),
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return service.create_organization(payload, token, user_service)


@router.get("/organizations", tags=["organizations"])
async def organization_list(service: OrganizationService = Depends(OrganizationService)):
    return service.get_all_organizations()


@router.get("/me/organizations")
async def organizations_mine(
    token: str = Depends(oauth2_scheme), 
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return service.get_organizations_mine(token, user_service)


@router.post("/me/organizations/{organization_id}/members")
async def organization_modify_membership(
    organization_id: str,
    payload: ModifyOrganizationMembershipPayload,
    token: str = Depends(oauth2_scheme),
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return service.modify_organization_membership(organization_id, payload, token, user_service)


@router.post("/me/organizations/{organization_id}/leave")
async def organization_leave(
    organization_id: str,
    token: str = Depends(oauth2_scheme),
    service: OrganizationService = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return service.leave_organization(organization_id, token, user_service)

# ===== LINE ABOVE WHICH WORK IS DONE =====

@router.post("/me/organization/{organization_id}/owner/{user_id}")
async def organization_change_owner(
    organization_id: str,
    user_id: str,
    token: str = Depends(oauth2_scheme),
    service: OrganizaionServie = Depends(OrganizationService),
    user_service: UserService = Depends(UserService),
):
    return None

# ===== LINE ABOVE WHICH WIP =====

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
