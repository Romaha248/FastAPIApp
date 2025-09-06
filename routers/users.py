from fastapi import APIRouter, Depends, HTTPException
from ..models import Users
from ..database import SessionLocal
from sqlalchemy.orm import Session
from starlette import status
from pydantic import BaseModel, Field
from typing import Annotated
from .auth import get_current_user
from passlib.context import CryptContext

router = APIRouter(prefix="/users", tags=["users"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]
bcrypt_contex = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserPassVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)


@router.get("/info", status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Not auth")

    return db.query(Users).filter(Users.id == user.get("id")).first()


@router.put("/change_pass", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    user: user_dependency, db: db_dependency, pass_request: UserPassVerification
):
    if user is None:
        raise HTTPException(status_code=401, detail="Not auth")

    user_model = db.query(Users).filter(Users.id == user.get("id")).first()

    if not bcrypt_contex.verify(pass_request.password, user_model.hashed_password):
        raise HTTPException(status_code=401, detail="Error on pass change")

    user_model.hashed_password = bcrypt_contex.hash(pass_request.new_password)

    db.add(user_model)
    db.commit()


@router.put("/change_phone_number/{new_number}", status_code=status.HTTP_204_NO_CONTENT)
async def change_phone_number(
    user: user_dependency, db: db_dependency, new_number: str
):
    if user is None:
        raise HTTPException(status_code=401, detail="Not auth")

    user_model = db.query(Users).filter(Users.id == user.get("id")).first()

    user_model.phone_number = new_number

    db.add(user_model)
    db.commit()
