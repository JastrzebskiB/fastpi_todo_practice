from hashlib import sha256

from fastapi import Depends

from .dependency_injection import get_organization_service, get_user_service
from .dto import (
    CreateOrganizationPayload, 
    CreateUserPayload,
    OrganizationResponse,
    OrganizationResponseFlat, 
    UserResponse,
    UserResponseFlat,
)
from .models import Organization, User
from .repositories import (
    OrganizationRepository,
    UserRepository, 
    get_organization_repository,   
    get_user_repository,
)
from ..core import Session, settings


class UserService:
    def __init__(
        self, 
        repository: UserRepository = Depends(get_user_repository),
    ) -> None:
        self.repository = repository

    def create_user(
        self, 
        payload: CreateUserPayload, 
        organization_service: "OrganizationService" = Depends(get_organization_service) 
    ) -> UserResponse:
        self.validate_unique_user_fields(payload)
        user = self.create_domain_user_instance(payload)
        # TODO: How does "relationship" work as attribute names?!?!?!?!
        # what the fuuuuuuuuck? Shouldn't this be "owned organization/organization"?
        # are my tests that fucking useless?
        # or does clean architecture virtually require e2e tests?
        user = self.repository.create(user, attribute_names=["relationship"])
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
            password_hash=self.hash_password(payload),
            organization_id=payload.organization_id,
        )

    def hash_password(self, payload: CreateUserPayload) -> str:
        return sha256(payload.password.encode()).hexdigest()

    def create_user_response(
        self, 
        user: User, 
        organization_service: "OrganizationService"
    ) -> UserResponse:
        # breakpoint()
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
    
    def create_user_response_flat(self, user: User) -> UserResponseFlat:
        return UserResponseFlat(id=user.id, email=user.email, username=user.username)


class OrganizationService:
    def __init__(
        self,
        repository: OrganizationRepository = Depends(get_organization_repository),
    ) -> None:
        self.repository = repository
    
    # TODO: needs test, start with adding tests here
    def create_organization(
        self, 
        payload: CreateOrganizationPayload, 
        user_service: UserService = Depends(get_user_service),
    ) -> OrganizationResponse:
        self.validate_unique_organization_fields(payload)
        organization = self.create_domain_organization_instance(payload)
        organization = self.repository.create(organization, attribute_names=["relationship"])
        owner, members = self.add_users_to_organization(organization.id, payload, user_service)

        return self.create_organization_response(organization, owner, members)

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
        organization_id: str, # TODO: uuid4
        payload: CreateOrganizationPayload, 
        user_service: UserService,
    ) -> tuple[UserResponseFlat, list[UserResponseFlat]]:
        # TODO: not sure if this is necessary?
        if not self.repository.exists_with_id(organization_id):
            raise ValueError(f"Organization with id {organization_id} doesn't exist.")
        
        member_ids = [payload.owner_id, *payload.member_ids]
        members = user_service.repository.add_users_to_organization(organization_id, member_ids)
        owner, members = members[0], members[1:]

        return (
            user_service.create_user_response_flat(owner),
            [user_service.create_user_response_flat(member) for member in members]
        )

    def create_organization_response(
        self, 
        organization: Organization, 
        owner: UserResponseFlat, 
        members: list[UserResponseFlat], 
    ) -> OrganizationResponse:
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
