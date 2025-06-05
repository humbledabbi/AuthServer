from pydantic import BaseModel
from typing import Optional
from .auth import hash_password, verify_password

# Fake in-memory "database"
fake_db = {}

class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    hashed_password: str

def create_user(user: User):
    if user.username in fake_db:
        return None
    hashed_pw = hash_password(user.password)
    fake_db[user.username] = {
        "username": user.username,
        "hashed_password": hashed_pw
    }
    return user.username

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = fake_db.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return UserInDB(
        username=username,
        password=password,
        hashed_password=user["hashed_password"]
    )
