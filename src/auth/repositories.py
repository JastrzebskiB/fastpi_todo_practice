from sqlalchemy.sql import exists, select, update
from sqlalchemy.orm import joinedload

from ..core import BaseRepository, Session
from .models import Organization, OrganizationAccessRequest, User


class UserRepository(BaseRepository):
    model = User

    def get_by_id(
        self, 
        user_id: str,
        relationships: list = [joinedload(User.owned_organization), joinedload(User.organizations)]
    ) -> User | None:
        return super().get_by_id(user_id, relationships=relationships)

    def get_by_email_and_password(self, email: str, password_hash: str) -> User:
        with self.sessionmaker() as session:
            return session.scalar(
                select(self.model).where(
                    self.model.email == email,
                    self.model.password_hash == password_hash,
                )
            )

    def check_username_exists(self, username: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(exists().where(self.model.username == username).select())

    def check_email_exists(self, email: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(exists().where(self.model.email == email).select())

    def check_username_unique(self, username: str) -> bool:
        with self.sessionmaker() as session:
            return not self.check_username_exists(username)

    def check_email_unique(self, email: str) -> bool:
        with self.sessionmaker() as session:
            return not self.check_email_exists(email)

    def get_user_by_email(self, email: str) -> User:
        with self.sessionmaker() as session:
            result = session.execute(
                select(self.model).where(self.model.email == email)
            ).first()
            return result[0] if result else None


class OrganizationRepository(BaseRepository):
    model = Organization

    def add_users_to_organizations_by_id(
        self, 
        users: list[User], 
        organization_ids: list[str],
    ) -> None:
        with self.sessionmaker() as session:
            organizations = session.scalars(
                select(self.model).where(self.model.id.in_(organization_ids))
            ).all()
            # TODO: Add test - what happens when you try to add someone to an org they are already 
            # a member of?
            for organization in organizations:
                organization.members.extend(users)
                session.add(organization)
            session.commit()

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

    def get_by_owner_email(self, owner_email: str) -> list[Organization]:
        with self.sessionmaker() as session:
            return session.execute(
                select(self.model).
                join(User, self.model.owner_id == User.id).
                where(User.email == owner_email)
            ).scalars().all()

    def get_by_owner_id(self, owner_id: str) -> list[Organization]:
        with self.sessionmaker() as session:
            return session.execute(
                select(self.model).where(self.model.owner_id == owner_id)
            ).scalars().all()

    def check_name_unique(self, name: str) -> bool:
        with self.sessionmaker() as session:
            return not session.scalar(exists().where(self.model.name == name).select())


class OrganizationAccessRequestRepository(BaseRepository):
    model = OrganizationAccessRequest

    def check_request_uniqueness(self, requester_id: str, organization_id: str) -> bool:
        with self.sessionmaker() as session:
            return not session.scalar(
                exists().where(
                    self.model.requester_id == requester_id,
                    self.model.organization_id == organization_id,
                ).select()
            )

    def get_pending_for_organization(
        self, 
        organization_id: str,
    ) -> list[OrganizationAccessRequest]:
        with self.sessionmaker() as session:
            return session.execute(
                select(self.model).where(
                    self.model.organization_id == organization_id,
                    self.model.approved == None,  # is None doesn't work here!
                )
            ).scalars().all()
