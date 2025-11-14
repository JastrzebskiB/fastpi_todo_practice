from pydantic import BaseModel, EmailStr, UUID4


class CreateUserPayload(BaseModel):
    email: EmailStr
    username: str
    password: str

    # organization_id?


class UserResponse(BaseModel):
    id: UUID4
    email: EmailStr
    username: str

    # Will be added once I have DTOs for those
    # owned_organization
    # organization


class CreateOrganizationPayload(BaseModel):
    ...
