from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from fastapi import Depends
from fastapi.params import Depends as DependsType
from jwt import decode as jwt_decode, encode as jwt_encode, exceptions as jwt_exceptions

from ..core.config import settings
from .dependency_injection import get_organization_service, get_user_service
from .dto import (
    CreateOrganizationAccessRequestPayload,
    CreateOrganizationPayload, 
    CreateUserPayload,
    JWToken,
    OrganizationAccessRequestResponse,
    OrganizationResponse,
    OrganizationResponseFlat,
    UserResponse,
    UserResponseFlat,
)
from .exceptions import AuthenticationFailedException, BadJWTException
from .models import OrganizationAccessRequest, Organization, User
from .repositories import (
    OrganizationRepository,
    OrganizationAccessRequestRepository,
    UserRepository, 
    get_organization_repository,
    get_organization_access_request_repository,
    get_user_repository,
)


class UserService:
    def __init__(
        self, 
        repository: UserRepository = Depends(get_user_repository),
    ) -> None:
        if isinstance(repository, DependsType):
            print(f"{repository=}", flush=True)  # TODO: Remove this whole branch?
            repository = repository.dependency()
        self.repository = repository

    # TODO: Should the security methods be in this service?
    def hash_password(self, password: str) -> str:
        return sha256(password.encode()).hexdigest()

    # TODO: Should the security methods be in this service?
    # TODO: should the data be passed as a dict?
    def create_jwt(self, jwt_data: dict) -> JWToken:
        return JWToken(
            access_token=jwt_encode(
                jwt_data, 
                settings.JWT_SECRET_KEY, 
                algorithm=settings.JWT_ALGORITHM,
            )
        )

    # TODO: Should the security methods be in this service?
    def sign_user_in(
        self, 
        email: str, 
        password: str, 
        expiration_minutes: timedelta = timedelta(minutes=settings.jwt_expiration)
    ) -> JWToken | None:
        user = self.repository.get_user_by_email_and_password(email, self.hash_password(password))
        if not user:
            raise AuthenticationFailedException

        return self.create_jwt({"sub": user.email, "exp": datetime.utcnow() + expiration_minutes})

    def get_by_id(self, user_id: str) -> UserResponseFlat | None:
        return self.create_user_response_flat(self.repository.get_by_id(user_id))

    def get_current_user(self, token: JWToken) -> UserResponseFlat | None:
        try:
            payload = jwt_decode(
                token, 
                settings.JWT_SECRET_KEY, 
                algorithms=[settings.JWT_ALGORITHM],
            )
            email = payload.get("sub")
        except jwt_exceptions.InvalidTokenError as e:
            raise AuthenticationFailedException

        if email is None:
            raise BadJWTException
        return self.create_user_response_flat(self.repository.get_user_by_email(email))

    def create_user(
        self, 
        payload: CreateUserPayload, 
        organization_service: "OrganizationService" 
    ) -> UserResponse:
        self.validate_unique_user_fields(payload)
        user = self.create_domain_user_instance(payload)
        user = self.repository.create(user, attribute_names=["owned_organization", "organization"])
        return self.create_user_response(user, organization_service)

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
            raise ValueError(
                f"The following {field} {contain} non-unique {value}: {duplicate_fields}"
            )

    def create_domain_user_instance(self, payload: CreateUserPayload) -> User:
        return User(
            email=payload.email,
            username=payload.username,
            password_hash=self.hash_password(payload.password),
            organization_id=payload.organization_id,
        )

    def create_user_response(
        self, 
        user: User, 
        organization_service: "OrganizationService"
    ) -> UserResponse:
        owned_organization = (
            organization_service.create_organization_response_flat(user.owned_organization)
            if user.owned_organization else None
        )
        organization = (
            organization_service.create_organization_response_flat(user.organization) 
            if user.organization_id else None
        )
        return UserResponse(
            id=user.id, 
            email=user.email, 
            username=user.username,
            owned_organization=owned_organization,
            organization=organization,
        )
    
    def create_user_response_flat(self, user: User) -> UserResponseFlat | None:
        if not user:
            return None
        return UserResponseFlat(id=user.id, email=user.email, username=user.username)


class OrganizationService:
    def __init__(
        self, 
        repository: OrganizationRepository = Depends(get_organization_repository)
    ) -> None:
        if isinstance(repository, DependsType):
            print(f"{repository=}", flush=True)  # TODO: Remove this whole branch?
            repository = repository.dependency()
        self.repository = repository

    def get_by_id(self, organization_id: str) -> OrganizationResponseFlat | None:
        return self.create_organization_response_flat(self.repository.get_by_id(organization_id))

    def get_all(self, user_service: UserService) -> list[OrganizationResponse]:
        return [
            self.create_organization_response(organization, user_service)
            for organization in self.repository.get_all()
        ]
 
    def create_organization(
        self, 
        payload: CreateOrganizationPayload, 
        user_service: UserService,  # TODO: Are dependencies like this REALLY ok?
    ) -> OrganizationResponse:
        self.validate_unique_organization_fields(payload)
        organization = self.create_domain_organization_instance(payload)
        organization = self.repository.create(
            organization,
            attribute_names=["owner", "members"]
        )
        self.add_users_to_organization(organization.id, payload, user_service)
        # TODO: Ugly that we have to call a SELECT right after creating, this all should be 
        # a single atomic operation
        organization = self.repository.get_by_id(str(organization.id))

        return self.create_organization_response(organization, user_service)

    def validate_unique_organization_fields(self, payload: CreateOrganizationPayload) -> None:
        if not self.repository.check_name_unique(payload.name):
            raise ValueError("The following field contains non-unique value: ['name']")

    def create_domain_organization_instance(
        self, 
        payload: CreateOrganizationPayload,
    ) -> Organization:
        return Organization(name=payload.name, owner_id=payload.owner_id)

    def add_users_to_organization(
        self, 
        organization_id: UUID,
        payload: CreateOrganizationPayload, 
        user_service: UserService,
    ) -> None:
        if not self.repository.exists_with_id(organization_id):
            raise ValueError(f"Organization with id {organization_id} doesn't exist.")
        
        member_ids = [payload.owner_id, *payload.member_ids]
        members = user_service.repository.add_users_to_organization(organization_id, member_ids)

    def create_organization_response(
        self, 
        organization: Organization, 
        user_service: UserService, 
    ) -> OrganizationResponse:
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


class OrganizationAccessRequestService:
    def __init__(
        self, 
        repository: OrganizationAccessRequestRepository = Depends(
            get_organization_access_request_repository
        ),
    ) -> None:
        if isinstance(repository, DependsType):
            print(f"{repository=}", flush=True)  # TODO: Remove this whole branch?
            repository = repository.dependency()
        self.repository = repository

    def create_organization_access_request(
        self, 
        payload: CreateOrganizationAccessRequestPayload,
        user_service: UserService,
        organization_service: OrganizationService,
    ) -> OrganizationAccessRequestResponse:
        self.validate_data(payload, user_service, organization_service)
        access_request = self.create_domain_organization_access_request_instance(payload)
        access_request = self.repository.create(access_request)
        return self.create_organization_access_request_response(access_request)

    def create_domain_organization_access_request_instance(
        self, 
        payload: CreateOrganizationAccessRequestPayload,
    ) -> OrganizationAccessRequest:
        return OrganizationAccessRequest(
            requester_id=payload.requester_id, 
            organization_id=payload.organization_id
        )

    def validate_data(
        self, 
        payload: CreateOrganizationAccessRequestPayload, 
        user_service: UserService, # TODO: Are dependencies like these REALLY ok?
        organization_service: OrganizationService,  
    ) -> None:
        # req_id = str(payload.requester_id)
        # org_id = str(payload.organization_id)
        # breakpoint()
        # exists = self.repository.check_request_uniqueness(req_id, org_id)
        if not self.repository.check_request_uniqueness(
            str(payload.requester_id), str(payload.organization_id)
        ):
            # TODO: Start here!
            # Should we raise all exceptions in the same format as in exceptions.py?
            # The answer is a RESOUNDING yes!
            raise ValueError(f"The following OrganizationAccessRequest already exists.")

        # TODO: What if requesting user is already an owner of another Organization?
        # TODO: What if requesting user is THE ONLY member of another Organization?

        user = user_service.get_by_id(payload.requester_id)
        if not user:
            raise ValueError(f"User with id {payload.requester_id} doesn't exist.")

        organization = organization_service.get_by_id(payload.organization_id)
        if not organization:
            raise ValueError(f"Organization with id {payload.organization_id} doesn't exist.")

    def create_organization_access_request_response(
        self, 
        organization_access_request: OrganizationAccessRequest,
    ) -> OrganizationAccessRequestResponse:
        return OrganizationAccessRequestResponse(
            id=organization_access_request.id,
            requester_id=organization_access_request.requester_id,
            organization_id=organization_access_request.organization_id,
            approved=organization_access_request.approved,
        )
