import uuid
from typing import Optional

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..core.db import Base, CommonFieldsMixin


class Board(Base, CommonFieldsMixin):
    __tablename__ = "board"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="board_name_organization_unique"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(nullable=False)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id"), nullable=False
    )


class Column(Base, CommonFieldsMixin):
    __tablename__ = "column"
    __table_args__ = (
        UniqueConstraint("board_id", "name", name="column_name_board_unique"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(nullable=False)
    order: Mapped[int] = mapped_column(nullable=False, default=0)

    board_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("board.id"), nullable=False)


class Task(Base, CommonFieldsMixin):
    __tablename__ = "task"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(nullable=False)
    description: Mapped[str] = mapped_column(nullable=True)
    order: Mapped[int] = mapped_column(nullable=False, default=0)

    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"), nullable=False)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("user.id"), nullable=True
    )
    in_column: Mapped[uuid.UUID] = mapped_column(ForeignKey("column.id"), nullable=False)
