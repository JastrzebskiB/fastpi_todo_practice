from sqlalchemy.orm import joinedload
from sqlalchemy.sql import delete, exists, or_, select, update

from ..core import BaseRepository, Session
from .models import Organization, OrganizationAccessRequest, User, organization_member_join_table


class UserRepository(BaseRepository):
    model = User

    def get_user_by_email_and_password(self, email: str, password_hash: str) -> User:
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
            return session.scalar(select(self.model).where(self.model.email == email))

    def delete_user_by_email(self, email: str) -> None:
        with self.sessionmaker() as session:
            user = session.scalar(select(self.model).where(self.model.email == email))
            session.delete(user)
            session.commit()
        
        return None


class OrganizationRepository(BaseRepository):
    model = Organization

    def check_name_exists(self, name: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(exists().where(self.model.name == name).select())

    def check_name_unique(self, name: str) -> bool:
        with self.sessionmaker() as session:
            return not self.check_name_exists(name)

    def create_organization_with_members(
        self, 
        organization: Organization, 
        member_ids: list[str],
    ) -> Organization:
        with self.sessionmaker() as session:
            try:
                organization.members = session.scalars(
                    select(User).where(User.id.in_(member_ids))
                ).all()
                session.add(organization)
                session.commit()
                session.refresh(organization, attribute_names=["owner", "members"])
            except Exception as e:
                session.rollback()
                raise e
        return organization

    def get_all_organizations(
        self, 
        relationships: list = [joinedload(Organization.owner), joinedload(Organization.members)]
    ) -> list[Organization]:
        return super().get_all(relationships=relationships)

    def get_organizations_with_member_or_owner(self, user_id: str) -> list[Organization]:
        with self.sessionmaker() as session:
            return session.scalars(
                select(self.model)
                .join(organization_member_join_table, isouter=True)
                .options(
                    joinedload(self.model.owner),
                    joinedload(self.model.members),
                )
                .where(
                    or_(
                        self.model.owner_id == user_id,
                        organization_member_join_table.c.member_id == user_id,
                    ),
                )
            ).unique().all()

    # === LINE ABOVE WHICH WORK IS DONE ===

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
