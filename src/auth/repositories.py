from datetime import datetime, timedelta

from sqlalchemy.orm import joinedload
from sqlalchemy.sql import delete, exists, or_, select, update

from ..core import BaseRepository, Session, settings
from . import exceptions
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

    def check_organization_with_id_and_owner_id_exists(
        self, 
        organization_id: str, 
        owner_id: str,
    ) -> Organization:
        with self.sessionmaker() as session:
            return session.scalar(
                exists()
                .where(self.model.id == organization_id, self.model.owner_id == owner_id)
                .select()
            )
    
    def check_organization_with_id_exists(self, organization_id: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(exists().where(self.model.id == organization_id).select())

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

    # TODO: Make the logic more modular and reuse it in remove members/leave org/change owner
    def add_members_to_organization_by_id(
        self, 
        member_ids_to_add: list[str], 
        organization_id: str,
    ) -> Organization:
        with self.sessionmaker() as session:
            try:
                organization = session.scalar(
                    select(self.model).where(self.model.id == organization_id)
                )
                # Make the operation idempotent: we only add the members who aren't already members
                # of the organization
                existing_member_ids = set([str(member.id) for member in organization.members])
                member_ids_to_add = set(member_ids_to_add)
                member_ids_to_add = member_ids_to_add - existing_member_ids
                if member_ids_to_add:
                    organization.members.extend(
                        session.scalars(select(User).where(User.id.in_(member_ids_to_add))).all()
                    )
                    session.add(organization)
                    session.commit()
                session.refresh(organization, attribute_names=["owner", "members"])
            except Exception as e:
                session.rollback()
                raise e
        return organization

    def remove_members_from_organization_by_id(
        self, 
        member_ids_to_remove: list[str], 
        organization_id: str,
    ) -> Organization:
        with self.sessionmaker() as session:
            try:
                organization = session.scalar(
                    select(self.model).where(self.model.id == organization_id)
                )
                # Make the operation idempotent: we only remove actual members
                existing_member_ids = set([str(member.id) for member in organization.members])
                member_ids_to_remove = set(member_ids_to_remove)
                member_ids_to_remove = member_ids_to_remove & existing_member_ids
                if member_ids_to_remove:
                    members_to_remove = session.scalars(
                        select(User).where(User.id.in_(member_ids_to_remove))
                    ).all()
                    for member in members_to_remove:
                        organization.members.remove(member)
                    session.add(organization)
                    session.commit()
                session.refresh(organization, attribute_names=["owner", "members"])
            except Exception as e:
                session.rollback()
                raise e
        return organization

    def remove_member_from_organization_by_id(
        self, 
        member_id: str, 
        organization_id: str,
    ) -> Organization:
        with self.sessionmaker() as session:
            organization = session.scalar(
                select(self.model).where(self.model.id == organization_id)
            )
            # Disallow leaving as owner - you can only delete the org if you're the last member left
            if member_id == str(organization.owner_id):
                session.refresh(organization, attribute_names=["owner", "members"])
                return organization
            try:
                organization.members.remove(
                    session.scalar(select(User).where(User.id == member_id))
                )
                session.add(organization)
                session.commit()
            # Idempotent: do not raise exception if trying to leave an org you're not a member of
            except ValueError:
                session.rollback()
            except Exception as e:
                session.rollback()
                raise e
            session.refresh(organization, attribute_names=["owner", "members"])

        return organization

    def change_organization_owner(self, new_owner_id: str, organization_id: str) -> Organization:
        with self.sessionmaker() as session:
            try:
                organization = session.scalar(
                    select(self.model)
                    .options(joinedload(self.model.members))
                    .where(self.model.id == organization_id)
                )
                organization.owner_id = new_owner_id
                if new_owner_id not in [str(member.id) for member in organization.members]:
                    organization.members.extend(
                        session.scalars(select(User).where(User.id == new_owner_id)).all()
                    )
                session.add(organization)
                session.commit()
                session.refresh(organization, attribute_names=["owner", "members"])
            except Exception as e:
                session.rollback()
                raise e
        return organization

    def delete_organization(self, organization_id) -> tuple[str, bool]:
        with self.sessionmaker() as session:
            organization = session.scalar(
                select(self.model)
                .options(
                    joinedload(self.model.members)
                )
                .where(self.model.id == organization_id)
            )
            if len(organization.members) > 1:
                return "Cannot delete an organization that still has other members", False
            session.delete(organization)
            session.commit()
        return "Organization deleted successfully", True


class OrganizationAccessRequestRepository(BaseRepository):
    model = OrganizationAccessRequest

    def validate_access_request(self, requester_id: str, organization_id: str) -> None:
        with self.sessionmaker() as session:
            organization = session.scalar(
                select(Organization)
                .options(joinedload(Organization.members))
                .where(Organization.id == organization_id)
            )
            if requester_id in [str(member.id) for member in organization.members]:
                raise exceptions.ValidationException(
                    detail="You are already a member of this Organization"
                )
            existing_access_request = session.scalar(
                select(self.model)
                .where(
                    self.model.requester_id == requester_id,
                    self.model.organization_id == organization_id
                )
            )
            if not existing_access_request:
                return

            updated_recently = (existing_access_request.updated_at 
                    + timedelta(days=settings.organization_access_request_resubmission)
                    > datetime.now()
            )

            if existing_access_request.approved is None:
                raise exceptions.ValidationException(
                    detail=(
                        "You already requested access to this Organization. "
                        "Your request awaits processing"
                    )
                )
            elif not existing_access_request.approved and updated_recently:
                updated_at = existing_access_request.updated_at.strftime("%Y-%m-%d %H:%M:%S")
                raise exceptions.ValidationException(
                    detail=(
                        f"You access request for this Organization was denied on {updated_at}. "
                        f"Wait for at least {settings.organization_access_request_resubmission} "
                        "days before resubmitting your request."
                    )
                ) 

#     def get_pending_for_organization(
#         self, 
#         organization_id: str,
#     ) -> list[OrganizationAccessRequest]:
#         with self.sessionmaker() as session:
#             return session.execute(
#                 select(self.model).where(
#                     self.model.organization_id == organization_id,
#                     self.model.approved == None,  # is None doesn't work here!
#                 )
#             ).scalars().all()
