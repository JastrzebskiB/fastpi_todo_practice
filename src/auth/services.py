from hashlib import sha256

from .dto import CreateUserPayload
from .models import User
from ..core import Session, settings


def create_user(payload: CreateUserPayload) -> User | dict[str, str]:
    ...
    # 1. check if email/username exists? Or just try creating one and if it fails catch the exception?
    # 2. hash password
    # 3. check if organization exists (if it gets passed in the payload)
    # 4. create user, return it 


def validate_unique_fields(payload: CreateUserPayload) -> dict[str, str] | None:
    with Session(settings.db_conn_url) as session:
        username_exists = session.query(User).filter_by(username=payload.username).exists()
        mail_exists = session.query(User).filter_by(username=payload.username).exists()

    return 
