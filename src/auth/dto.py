from typing import Optional

from pydantic import BaseModel, EmailStr, UUID4


class CreateUserPayload(BaseModel):
    email: EmailStr
    username: str
    password: str
    organization_id: UUID4 | None = None


class UserResponse(BaseModel):
    id: UUID4
    email: EmailStr
    username: str

    owned_organization: Optional["OrganizationResponseFlat"]
    organization: Optional["OrganizationResponseFlat"]


class CreateOrganizationPayload(BaseModel):
    name: str
    owner: UserResponse
    members: list[UserResponse]     


class OrganizationResponseFlat(BaseModel):
    id: UUID4
    name: str


class OrganizationResponse(BaseModel):
    ...
