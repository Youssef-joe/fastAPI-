from sqlalchemy import Column, Integer, String
from database import Base

class User(Base):
    _tablename_ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, unique=True, nullable=False)
    hashedPass = Column(String, nullable=False)