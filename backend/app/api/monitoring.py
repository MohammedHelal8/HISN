
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.auth_dependencies import get_current_user
from app.models.administrator import Administrator
from app.services.monitoring_service import (
    get_monitoring_overview,
)


router = APIRouter(
    prefix="/monitoring",
    tags=["Monitoring"],
)


@router.get("/overview")
def monitoring_overview(
    user: Annotated[
        Administrator,
        Depends(get_current_user),
    ],
):
    return get_monitoring_overview()
