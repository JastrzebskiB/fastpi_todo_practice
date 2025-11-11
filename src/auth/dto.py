from pydantic import BaseModel, EmailStr


class CreateUserPayload(BaseModel):
    email: EmailStr
    username: str
    password_hash: str

    # organization_id?
