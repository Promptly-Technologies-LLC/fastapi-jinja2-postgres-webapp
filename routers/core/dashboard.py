from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from utils.core.dependencies import get_user_with_relations
from utils.core.models import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
templates = Jinja2Templates(directory="templates")


# --- Authenticated Routes ---


@router.get("/")
async def read_dashboard(
    request: Request,
    user: Optional[User] = Depends(get_user_with_relations)
):
    return templates.TemplateResponse(
        "dashboard/index.html",
        {"request": request, "user": user}
    )