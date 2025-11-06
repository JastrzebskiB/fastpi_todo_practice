import uuid
from datetime import datetime
from typing import Optional, List

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from ..core.db import Base, CommonFieldsMixin


class Organization(Base, CommonFieldsMixin):
    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(unique=True, nullable=False)

    # one-to-many relationship ("one" side):
    # relationship foreign_keys arg: "[ClassName.field_name]"
    members: Mapped[List["User"]] = relationship(
        foreign_keys="[User.organization_id]",
        back_populates="organization", 
        viewonly=True,
    )
    # one-to-one relationship:
    # ForeignKey: "table_name.field_name"  (field exists in related table)
    # relationship foreign_keys arg: field_name (field exists in this table)
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

    # one-to-one relationship
    # relationship foreign_keys arg: "ClassName.field_name" (field exists in related table)
    owned_organization: Mapped["Organization"] = relationship(
        foreign_keys="Organization.owner_id", 
        back_populates="owner",
    )
    # many-to-one relationship ("many" side):
    # ForeignKey: "table_name.field_name" (field exists in related table)
    # relationship foreign_keys arg: field_name (field exists in this table)
    # organization_id and organization relationship create a many-to-one relationship
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("organization.id"), 
        nullable=True,
    )
    organization: Mapped[Optional["Organization"]] = relationship(
        foreign_keys=[organization_id],
        back_populates="members",
    )

    def __repr__(self):
        return f"<src.auth.models.User: {self.username}>"
