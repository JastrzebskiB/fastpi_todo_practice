from ..core import BaseRepository, Session
from .models import User


class UserRepository(BaseRepository):
    model = User
