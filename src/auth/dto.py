from typing import Optional

from pydantic import BaseModel, EmailStr, UUID4


class JWToken(BaseModel):
    token_type: str = "bearer"
    access_token: str


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


class UserResponseFlat(BaseModel):
    id: UUID4
    email: EmailStr
    username: str


class CreateOrganizationPayload(BaseModel):
    name: str

    owner_id: UUID4  
    member_ids: list[UUID4]


class OrganizationResponseFlat(BaseModel):
    id: UUID4
    name: str


class OrganizationResponse(BaseModel):
    id: UUID4
    name: str

    owner: UserResponseFlat
    members: list[UserResponseFlat]


class OrganizationAccessRequestResponse(BaseModel):
    id: UUID4
    requester_id: UUID4
    organization_id: UUID4
    approved: bool | None


class OrganizationAccessRequestDecisionPayload(BaseModel):
    approve: bool
