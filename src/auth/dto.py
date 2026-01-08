from typing import Optional

from pydantic import BaseModel, EmailStr, UUID4


class JWToken(BaseModel):
    token_type: str = "bearer"
    access_token: str


# User
class CreateUserPayload(BaseModel):
    email: EmailStr
    username: str
    password: str


class UserResponse(BaseModel):
    id: UUID4
    email: EmailStr
    username: str

    owned_organization: Optional["OrganizationResponseFlat"]
    organizations: list["OrganizationResponseFlat"]


class UserResponseFlat(BaseModel):
    id: UUID4
    email: EmailStr
    username: str


# Organization
class CreateOrganizationPayload(BaseModel):
    name: str

    member_ids: list[UUID4]


class OrganizationResponseFlat(BaseModel):
    id: UUID4
    name: str


class OrganizationResponse(BaseModel):
    id: UUID4
    name: str

    owner: UserResponseFlat
    members: list[UserResponseFlat]


# Organization Access Request
class OrganizationAccessRequestResponse(BaseModel):
    id: UUID4
    requester_id: UUID4
    organization_id: UUID4
    approved: bool | None


class OrganizationAccessRequestDecisionPayload(BaseModel):
    approve: bool
