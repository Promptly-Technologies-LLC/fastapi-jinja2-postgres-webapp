from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from utils.dependencies import get_optional_user
from utils.models import User

router = APIRouter(prefix="/privacy_policy", tags=["privacy_policy"])
templates = Jinja2Templates(directory="templates")

@router.get("/")
async def read_privacy_policy(
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    return templates.TemplateResponse(
        "privacy_policy.html",
        {"request": request, "user": user}
    )
