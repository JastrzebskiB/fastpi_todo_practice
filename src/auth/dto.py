from pydantic import BaseModel, EmailStr


class CreateUserPayload(BaseModel):
    email: EmailStr
    username: str
    password_hash: str  # Doesn't actually come hashed, gets hashed in CreateUserService

    # organization_id?
