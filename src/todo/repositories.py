from sqlalchemy.orm import joinedload
from sqlalchemy.orm.session import Session as SessionType
from sqlalchemy.sql import delete, exists, or_, select, update

from ..core import BaseRepository, Session, settings
from .models import Board, Column, Task


class BoardRepository(BaseRepository):
    model = Board

    def check_name_unique_in_organization(self, name: str, organization_id: str) -> bool:
        return not self.check_name_exists_in_organization(name, organization_id)

    def check_name_exists_in_organization(self, name: str, organization_id: str) -> bool:
        with self.sessionmaker() as session:
            return session.scalar(
                exists().where(
                    self.model.name == name, 
                    self.model.organization_id == organization_id,
                ).select()
            )
