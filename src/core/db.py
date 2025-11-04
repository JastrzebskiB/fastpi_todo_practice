from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    ...


engine = create_engine(settings.db_conn_url)
# TODO: Consider expire_on_commit=False? https://docs.sqlalchemy.org/en/20/errors.html#error-bhk3
Session = sessionmaker(engine)  
