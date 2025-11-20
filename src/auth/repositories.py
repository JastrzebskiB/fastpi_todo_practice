from sqlalchemy.sql import exists, update

from ..core import BaseRepository, Session
from .models import Organization, User


class UserRepository(BaseRepository):
    model = User

    def check_username_unique(self, username: str) -> bool:
        with self.sessionmaker() as session:
            # I think I love this syntax?
            # https://stackoverflow.com/a/75900879
            return not session.scalar(exists().where(self.model.username == username).select())

    def check_email_unique(self, email: str) -> bool:
        with self.sessionmaker() as session:
            return not session.scalar(exists().where(self.model.email == email).select())

    def add_users_to_organization(self, organization_id: str, member_ids: list[str]) -> list[User]:
        with self.sessionmaker() as session:
            session.execute(
                update(self.model),
                [
                    {"id": member_id, "organization_id": organization_id} 
                    for member_id in member_ids
                ]
            )
            session.commit()
            return self.get_all_by_id(member_ids)


def get_user_repository() -> UserRepository:
    return UserRepository()


class OrganizationRepository(BaseRepository):
    model = Organization

    def check_name_unique(self, name: str) -> bool:
        with self.sessionmaker() as session:
            return not session.scalar(exists().where(self.model.name == name).select())

    # which repo to put this in?
    # request access to organization?


def get_organization_repository() -> OrganizationRepository:
    return OrganizationRepository
