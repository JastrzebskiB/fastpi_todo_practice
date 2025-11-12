from sqlalchemy.sql import exists

from ..core import BaseRepository, Session
from .models import User


class UserRepository(BaseRepository):
    model = User

    def check_username_unique(self, username: str) -> bool:
        with self.sessionmaker() as session:
            # I think I love this syntax?
            # https://stackoverflow.com/a/75900879
            return not session.scalar(exists().where(self.model.username == username).select())

    def check_email_unique(self, email: str) -> bool:
        with self.sessionmaker() as session:
            # I think I love this syntax?
            # https://stackoverflow.com/a/75900879
            return not session.scalar(exists().where(self.model.email == email).select())


def get_user_repository() -> UserRepository:
    return UserRepository()
