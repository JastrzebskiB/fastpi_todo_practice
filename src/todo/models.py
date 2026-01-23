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
    organization: Mapped["Organization"] = relationship(foreign_keys=[organization_id])

    columns: Mapped[list["Column"]] = relationship(
        back_populates="board", order_by="Column.order, Column.created_at"
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
    board: Mapped["Board"] = relationship(back_populates="columns")

    tasks: Mapped[list["Task"]] = relationship(back_populates="column")


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
    column_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("column.id"), nullable=False)
    column: Mapped["Column"] = relationship(
        foreign_keys=[column_id],
        back_populates="tasks"
    )
