from datetime import UTC, datetime, timedelta
from hashlib import sha256

from fastapi import Depends
from fastapi.params import Depends as DependsType
from fastapi.security import OAuth2PasswordRequestForm
from jwt import decode as jwt_decode, encode as jwt_encode, exceptions as jwt_exceptions

from ..core import settings
from ..core.exceptions import ValidationException
from . import exceptions
from .dto import (
    CreateOrganizationPayload, 
    CreateUserPayload,
    JWToken,
    ModifyOrganizationMembershipPayload,
    OrganizationAccessRequestDecisionPayload,
    OrganizationAccessRequestResponse,
    OrganizationResponse,
    OrganizationResponseFlat,
    UserResponse,
    UserResponseFlat,
)
from .models import OrganizationAccessRequest, Organization, User
from .query_params import RequestAccessStatus
from .repositories import (
    OrganizationRepository,
    OrganizationAccessRequestRepository,
    UserRepository, 
)


class JWTService:
    @staticmethod
    def hash_password(password: str) -> str:
        return sha256(password.encode()).hexdigest()

    @staticmethod
    def create_jwt(jwt_data: dict) -> JWToken:
        if not jwt_data.get("exp"):
            jwt_data["exp"] = datetime.now(tz=UTC) + timedelta(minutes=settings.jwt_expiration)
        return JWToken(
            access_token=jwt_encode(
                jwt_data, 
                settings.JWT_SECRET_KEY, 
                algorithm=settings.JWT_ALGORITHM,
            )
        )

    @staticmethod
    def decode_jwt(token: str) -> dict:
        try:
            return jwt_decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        except jwt_exceptions.InvalidTokenError as e:
            raise exceptions.AuthenticationFailedException

    @staticmethod
    def validate_decoded_token_is_not_expired(decoded_token: dict) -> None:
        if (decoded_token["exp"] - datetime.now().timestamp()) <= 0:
            raise exceptions.ExpiredJWTException

    @staticmethod
    def get_user_email(token: str) -> dict:
        decoded_token = JWTService.decode_jwt(token)    
        JWTService.validate_decoded_token_is_not_expired(decoded_token)

        if (email := decoded_token.get("sub")) is None:
            raise exceptions.BadJWTException

        return email


class UserService:
    def __init__(self, repository: UserRepository = Depends(UserRepository)) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    def sign_user_in(
        self, 
        form_data: OAuth2PasswordRequestForm,
        expiration_minutes: timedelta = timedelta(minutes=settings.jwt_expiration),
        jwt_service: JWTService = JWTService,
    ) -> JWToken | None:
        email, password = form_data.username, form_data.password
        user = self.repository.get_user_by_email_and_password(
            email, jwt_service.hash_password(password)
        )
        if not user:
            raise exceptions.AuthenticationFailedException

        return jwt_service.create_jwt(
            {"sub": user.email, "exp": datetime.now(tz=UTC) + expiration_minutes}
        )

    def create_user(
        self, 
        payload: CreateUserPayload, 
        jwt_service: JWTService = JWTService,
    ) -> UserResponse:
        self.validate_unique_user_fields(payload)
        user = self.repository.create(self.create_domain_user_instance(payload, jwt_service))

        return self.create_user_response_flat(user)

    def get_current_user(
        self, 
        token: str, 
        check_user_exists: bool = False,
        jwt_service: JWTService = JWTService,
    ) -> UserResponseFlat | None:
        email = jwt_service.get_user_email(token)

        if check_user_exists and not self.repository.check_email_exists(email):
            raise exceptions.UserNotFound
        return self.create_user_response_flat(self.repository.get_user_by_email(email))

    def delete_current_user(self, token: str, jwt_service: JWTService = JWTService) -> None:
        email = jwt_service.get_user_email(token)

        if not self.repository.check_email_exists(email):
            raise exceptions.UserNotFound
        self.repository.delete_user_by_email(email)
        
        return None

    # Domain object manipulation
    def create_domain_user_instance(
        self, 
        payload: CreateUserPayload, 
        jwt_service: JWTService
    ) -> User:
        return User(
            email=payload.email,
            username=payload.username,
            password_hash=jwt_service.hash_password(payload.password),
        )

    # Validation
    def validate_unique_user_fields(self, payload: CreateUserPayload) -> None:
        duplicate_fields = []
    
        if not self.repository.check_username_unique(payload.username):
            duplicate_fields.append("username")
        if not self.repository.check_email_unique(payload.email):
            duplicate_fields.append("email")

        if duplicate_fields:
            # The pluralization bit is hilariously unnecessary, of course
            singular = len(duplicate_fields) == 1
            field = "field" if singular else "fields"
            contain = "contains" if singular else "contain"
            value = "value" if singular else "values"
            raise ValidationException(
                f"The following {field} {contain} non-unique {value}: {duplicate_fields}"
            )

    def validate_all_exist_by_id(self, user_ids: list[str]) -> None:
        users = self.repository.get_all_by_id(user_ids)
        missing_ids = set(user_ids) - set([str(user.id) for user in users])
        missing_ids = sorted(list(missing_ids))

        if missing_ids:
            singular = len(missing_ids) == 1
            user = "User" if singular else "Users"
            id_ = "id" if singular else "ids"
            raise ValidationException(f"{user} with the following {id_}: {missing_ids} not found")

    # Serialization
    def create_user_response(
        self, 
        user: User, 
        organization_service: "OrganizationService" = Depends("OrganizationService")
    ) -> UserResponse | None:
        if not user:
            return None

        owned_organization = (
            organization_service.create_organization_response_flat(user.owned_organization)
            if user.owned_organization else None
        )
        organizations = [
            organization_service.create_organization_response_flat(organization) 
            for organization in user.organizations
        ] if user.organizations else []
        return UserResponse(
            id=user.id, 
            email=user.email, 
            username=user.username,
            owned_organization=owned_organization,
            organizations=organizations,
        )
    
    def create_user_response_flat(self, user: User) -> UserResponseFlat | None:
        if not user:
            return None
        return UserResponseFlat(id=user.id, email=user.email, username=user.username)


class OrganizationService:
    def __init__(
        self, 
        repository: OrganizationRepository = Depends(OrganizationRepository),
    ) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    def create_organization(
        self, 
        payload: CreateOrganizationPayload, 
        token: str,
        user_service: UserService,
    ) -> OrganizationResponse:
        # Validate
        owner = user_service.get_current_user(token, check_user_exists=True)
        self.validate_unique_organization_fields(payload)
        member_ids = self.get_member_ids(owner, payload)
        user_service.validate_all_exist_by_id(member_ids)
        # Create
        organization = self.repository.create_organization_with_members(
            self.create_domain_organization_instance(owner, payload),
            member_ids,
        )

        return self.create_organization_response(organization, user_service)

    def get_all_organizations(self) -> list[OrganizationResponseFlat]:
        return [
            self.create_organization_response_flat(organization)
            for organization in self.repository.get_all_organizations(relationships=[])
        ]

    def get_organizations_mine(
        self, 
        token: str, 
        user_service: UserService,
    ) -> list[OrganizationResponse]:
        me = user_service.get_current_user(token, check_user_exists=True)
        organizations = self.repository.get_organizations_with_member_or_owner(me.id)

        return [
            self.create_organization_response(organization, user_service) 
            for organization in organizations
        ]
    
    def get_organizations_with_owner_id(self, owner_id: str) -> list[Organization]:
        return self.repository.get_organizations_with_owner_id(owner_id)

    def modify_organization_membership(
        self, 
        organization_id: str,
        payload: ModifyOrganizationMembershipPayload,
        token: str,
        user_service: UserService,
    ) -> OrganizationResponse:
        member_ids = [str(member_id) for member_id in payload.member_ids]
        add = payload.add
        return self.modify_organization_membership_by_ids(
            organization_id, member_ids, add, token, user_service,
        )

    def modify_organization_membership_by_ids(
        self, 
        organization_id: str,
        member_ids: list[str],
        add: bool,
        token: str,
        user_service: UserService,
    ) -> OrganizationResponse:
        # Validate
        me = user_service.get_current_user(token, check_user_exists=True)
        self.validate_organization_with_id_and_owner_id_exists(organization_id, me.id)
        user_service.validate_all_exist_by_id(member_ids)
        
        if add:
            organization = self.add_members_to_organization_by_id(member_ids, organization_id)
        else:
            if (me_id := str(me.id)) in member_ids:
                member_ids = [member_id for member_id in member_ids if member_id != me_id]
            organization = self.remove_members_from_organization_by_id(member_ids, organization_id)
        
        return self.create_organization_response(organization)

    def add_members_to_organization_by_id(
        self, 
        member_ids: list[str], 
        organization_id: str,
    ) -> Organization:
        return self.repository.add_members_to_organization_by_id(member_ids, organization_id)

    def remove_members_from_organization_by_id(
        self, 
        member_ids: list[str],
        organization_id: str,
    ) -> Organization:
        return self.repository.remove_members_from_organization_by_id(member_ids, organization_id)

    def leave_organization(
        self,
        organization_id: str,
        token: str,
        user_service: UserService,
    ) -> OrganizationResponse:
        me = user_service.get_current_user(token, check_user_exists=True)
        if not self.repository.check_organization_with_id_exists(organization_id):
            raise exceptions.OrganizationNotFound

        return self.create_organization_response(
            self.repository.remove_member_from_organization_by_id(str(me.id), organization_id)
        )
    
    def change_organization_owner(
        self,
        organization_id: str,
        new_owner_id: str,
        token: str,
        user_service: UserService
    ) -> OrganizationResponse:
        me = user_service.get_current_user(token)
        self.validate_organization_with_id_and_owner_id_exists(organization_id, me.id)
        user_service.validate_all_exist_by_id([str(me.id), new_owner_id])

        return self.create_organization_response(
            self.repository.change_organization_owner(new_owner_id, organization_id)
        )

    def delete_organization(
        self,
        organization_id: str,
        token: str,
        user_service: UserService,
    ) -> tuple[str, bool]:
        me = user_service.get_current_user(token)
        self.validate_organization_with_id_and_owner_id_exists(organization_id, me.id)
        
        return self.repository.delete_organization(organization_id)

    # Domain object manipulation 
    def create_domain_organization_instance(
        self, 
        owner: UserResponseFlat,
        payload: CreateOrganizationPayload,
    ) -> Organization:
        return Organization(name=payload.name, owner_id=owner.id)

    # Validation
    def validate_unique_organization_fields(self, payload: CreateOrganizationPayload) -> None:
        if not self.repository.check_name_unique(payload.name):
            raise ValidationException("The following field contains non-unique value: ['name']")

    def validate_organization_with_id_and_owner_id_exists(
        self, 
        organization_id: str, 
        owner_id: str,
    ) -> None:
        if not self.repository.check_organization_with_id_and_owner_id_exists(
            organization_id, owner_id
        ):
            raise exceptions.AuthorizationFailedException
    
    def validate_user_id_belongs_to_organization(self, organization_id: str, user_id: str) -> None:
        if not self.repository.check_user_id_belongs_to_organization(organization_id, user_id):
            raise exceptions.AuthorizationFailedException

    # Serialization
    def create_organization_response(
        self, 
        organization: Organization, 
        user_service: UserService = Depends(UserService),
    ) -> OrganizationResponse:
        if isinstance(user_service, DependsType):
            user_service = user_service.dependency()

        owner = user_service.create_user_response_flat(organization.owner)
        members = [
            user_service.create_user_response_flat(member) 
            for member in organization.members
        ]
        return OrganizationResponse(
            id=organization.id,
            name=organization.name,
            owner=owner,
            members=members,
        )

    def create_organization_response_flat(
        self, 
        organization: Organization,
    ) -> OrganizationResponseFlat:
        return OrganizationResponseFlat(id=organization.id, name=organization.name)

    # Helpers
    # TODO: Rethink if this is needed or if it should get generalized
    def get_member_ids(
        self, 
        owner: UserResponseFlat, 
        payload: CreateOrganizationPayload,
    ) -> list[str]:
        return [str(member_id) for member_id in set([owner.id, *payload.member_ids])]


class OrganizationAccessRequestService:
    def __init__(
        self, 
        repository: OrganizationAccessRequestRepository = Depends(
            OrganizationAccessRequestRepository
        ),
    ) -> None:
        if isinstance(repository, DependsType):
            repository = repository.dependency()
        self.repository = repository

    def request_organization_access(
        self, 
        organization_id: str,
        token: str,
        user_service: UserService,
        organization_service: OrganizationService,
    ) -> OrganizationAccessRequestResponse:
        requester_id = str(user_service.get_current_user(token, check_user_exists=True).id)
        self.validate_access_request_creation_data(organization_id, requester_id)
        
        access_request = self.create_domain_organization_access_request_instance(
            organization_id, requester_id
        )
        access_request = self.repository.create(access_request)
        return self.create_organization_access_request_response(access_request)

    def get_pending_requests_for_owned_organizations(
        self,
        token: str,
        user_service: UserService,
        status: RequestAccessStatus,
    ) -> list[OrganizationAccessRequestResponse]:
        me = user_service.get_current_user(token, check_user_exists=True)
        requests = self.repository.get_access_requests_for_owned_organizations_with_status(
            str(me.id), status.where_param
        )
        return [self.create_organization_access_request_response(request) for request in requests]

    def process_access_request(
        self, 
        access_request_id: str, 
        payload: OrganizationAccessRequestDecisionPayload,
        token: str, 
        user_service: UserService, 
        organization_service: OrganizationService,
    ) -> None:
        me = user_service.get_current_user(token, check_user_exists=True)
        access_request = self.repository.get_by_id(access_request_id)
        self.validate_access_request_can_be_processed_by_me(
            access_request, str(me.id), organization_service,
        )

        self.repository.process_access_request(access_request_id, payload.approve)
        if payload.approve:
            organization_service.add_members_to_organization_by_id(
                [access_request.requester_id], access_request.organization_id
            )

    # Domain objeect manipulation
    def create_domain_organization_access_request_instance(
        self, 
        organization_id: str,
        requester_id: str,
    ) -> OrganizationAccessRequest:
        return OrganizationAccessRequest(
            requester_id=requester_id, organization_id=organization_id,
        )

    # Validation
    def validate_access_request_creation_data(
        self, 
        organization_id: str, 
        requester_id: str, 
    ) -> None:
        # Exceptions raised within the repository
        self.repository.validate_access_request_can_be_created(requester_id, organization_id)

    def validate_access_request_can_be_processed_by_me(
        self, 
        access_request: OrganizationAccessRequest | None, 
        owner_id: str,
        organization_service: OrganizationService,
    ) -> None:
        if not access_request:
            raise exceptions.OrganizationAccessRequestNotFound
        # We're ok with approving a previously denied access request, so we only raise an exception
        # on an approved access request
        if access_request.approved is True:
            raise ValidationException("This access request has already been approved")

        organizations = organization_service.get_organizations_with_owner_id(owner_id)
        organization_ids = [organization.id for organization in organizations]
        if access_request.organization_id not in organization_ids:
            raise exceptions.AuthorizationFailedException

    # Serialization
    def create_organization_access_request_response(
        self, 
        organization_access_request: OrganizationAccessRequest,
    ) -> OrganizationAccessRequestResponse:
        return OrganizationAccessRequestResponse(
            id=organization_access_request.id,
            requester_id=organization_access_request.requester_id,
            organization_id=organization_access_request.organization_id,
            approved=organization_access_request.approved,
            updated_at=organization_access_request.updated_at,
        )
