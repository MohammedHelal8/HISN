
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.auth_dependencies import get_current_user
from app.models.administrator import Administrator


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


class CurrentUserResponse(BaseModel):
    id: int
    username: str
    role: Literal["admin", "viewer"]


@router.get("/me", response_model=CurrentUserResponse)
def get_me(
    user: Annotated[
        Administrator,
        Depends(get_current_user),
    ],
):
    return CurrentUserResponse(
        id=user.admin_id,
        username=user.username,
        role=user.role,
    )
