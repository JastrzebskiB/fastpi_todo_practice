from hashlib import sha256

from fastapi import Depends

from .dto import CreateUserPayload, OrganizationResponseFlat, UserResponse
from .models import Organization, User
from .repositories import (
    OrganizationRepository,
    UserRepository, 
    get_organization_repository,   
    get_user_repository,
)
from ..core import Session, settings


class CreateUserService:
    def __init__(
        self, 
        repository: UserRepository = Depends(get_user_repository),
    ) -> None:
        self.repository = repository

    def create_user(self, payload: CreateUserPayload) -> UserResponse:
        self.validate_unique_user_fields(payload)
        user = self.create_domain_user_instance(payload)
        user = self.repository.create(user, attribute_names=["relationship"])
        return self.create_user_response(user)

    def create_domain_user_instance(self, payload: CreateUserPayload) -> User:
        return User(
            email=payload.email,
            username=payload.username,
            password_hash=self.hash_password(payload),
            organization_id=payload.organization_id,
        )

    def create_organization_response(self, organization: Organization) -> OrganizationResponseFlat:
        return OrganizationResponseFlat(id=organization.id, name=organization.name)

    def create_user_response(self, user: User) -> UserResponse:
        owned_organization = (
            self.create_organization_response(user.owned_organization)
            if user.owned_organization else None
        )
        organization = (
            self.create_organization_response(user.organization) 
            if user.organization_id else None
        )
        return UserResponse(
            id=user.id, 
            email=user.email, 
            username=user.username,
            owned_organization=owned_organization,
            organization=organization,
        )

    def validate_unique_user_fields(self, payload: CreateUserPayload) -> None:
        duplicate_fields = []
    
        if not self.repository.check_username_unique(payload.username):
            duplicate_fields.append("username")
        if not self.repository.check_email_unique(payload.email):
            duplicate_fields.append("email")

        if duplicate_fields:
            singular = len(duplicate_fields) == 1
            field = "field" if singular else "fields"
            contain = "contains" if singular else "contain"
            raise ValueError(
                f"The following {field} {contain} non-unique values: {duplicate_fields}"
            )

    def hash_password(self, payload: CreateUserPayload) -> str:
        return sha256(payload.password.encode()).hexdigest()


def get_create_user_service():
    return CreateUserService


class CreateOrganizationService:
    def __init__(
        self,
        repository: OrganizationRepository = Depends(get_organization_repository),
    ) -> None:
        self.repository = repository


def get_create_organization_service():
    return CreateOrganizationService
