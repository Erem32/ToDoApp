from pydantic import BaseModel
from typing import List, Optional

class TaskBase(BaseModel):
    text: str

class Task(TaskBase):
    id: str
    user_id: str

    class Config:
        from_attributes = True

class TaskCreate(TaskBase):
    pass

class UserBase(BaseModel):
    username: str
    email: str
    name: str
    hashed_password: str

class User(UserBase):
    id: str
    tasks: List[Task] = []

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    pass