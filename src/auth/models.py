import uuid
from datetime import datetime
from typing import Optional, List

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from ..core.db import Base, CommonFieldsMixin


organization_member_join_table = Table(
    "organization_members_join_table",
    Base.metadata,
    Column("organization_id", ForeignKey("organization.id"), primary_key=True),
    Column("member_id", ForeignKey("user.id"), primary_key=True),
)


class Organization(Base, CommonFieldsMixin):
    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)

    # many-to-many relationships:
    members: Mapped[List["User"]] = relationship(
        secondary=organization_member_join_table,
        back_populates="organizations"
    )
    # one-to-one relationships:
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("user.id"), nullable=True)
    owner: Mapped[Optional["User"]] = relationship(
        foreign_keys=[owner_id], 
        back_populates="owned_organization",
    )


class User(Base, CommonFieldsMixin):
    __tablename__ = "user"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    username: Mapped[str] = mapped_column(unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(nullable=False)

    # one-to-one relationships:
    owned_organization: Mapped["Organization"] = relationship(
        foreign_keys="Organization.owner_id", 
        back_populates="owner",
    )
    # many-to-many relationships:
    organizations: Mapped[Optional["Organization"]] = relationship(
        secondary=organization_member_join_table,
        back_populates="members",
    )

    def __repr__(self):
        return f"<src.auth.models.User: {self.username}>"


class OrganizationAccessRequest(Base, CommonFieldsMixin):
    __tablename__ = "organization_access_request"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    requester_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id"), nullable=False
    )
    approved: Mapped[bool] = mapped_column(nullable=True)
