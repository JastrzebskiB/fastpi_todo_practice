from sqlalchemy.sql import exists, select, update
from sqlalchemy.orm import joinedload

from ..core import BaseRepository, Session
from .models import Organization, User


class UserRepository(BaseRepository):
    model = User

    def get_user_by_email_and_password(self, email: str, password_hash: str) -> User:
        with self.sessionmaker() as session:
            result = session.execute(
                select(self.model).where(
                    self.model.email == email,
                    self.model.password_hash == password_hash,
                )
            ).first()
            return result[0] if result else None
    
    def get_user_by_email(self, email: str) -> User:
        with self.sessionmaker() as session:
            result = session.execute(
                select(self.model).where(self.model.email == email)
            ).first()
            return result[0] if result else None

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

    def get_all(
        self, 
        relationships: list = [joinedload(Organization.owner), joinedload(Organization.members)]
    ) -> list[Organization]:
        return super().get_all(relationships=relationships)

    def get_by_id(
        self, 
        organization_id: str,
        relationships: list = [joinedload(Organization.owner), joinedload(Organization.members)]
    ) -> Organization | None:
        return super().get_by_id(organization_id, relationships=relationships)

    def check_name_unique(self, name: str) -> bool:
        with self.sessionmaker() as session:
            return not session.scalar(exists().where(self.model.name == name).select())


def get_organization_repository() -> OrganizationRepository:
    return OrganizationRepository()
