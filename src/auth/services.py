from hashlib import sha256

from fastapi import Depends

from .dto import CreateUserPayload
from .models import User
from .repositories import UserRepository, get_user_repository
from ..core import Session, settings


class CreateUserService:
    def __init__(
        self, 
        repository: UserRepository = Depends(get_user_repository)
    ) -> None:
        self.repository = repository

    def create_user(self, payload: CreateUserPayload) -> User:
        self.hash_password(payload)
        self.validate_unique_user_fields(payload)
        return self.repository.create(payload)

    def hash_password(self, payload: CreateUserPayload) -> None:
        payload.password_hash = sha256(payload.password_hash.encode()).hexdigest()

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


def get_create_user_service():
    return CreateUserService
