from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from utils.dependencies import get_optional_user
from utils.models import User

router = APIRouter(prefix="/about", tags=["about"])
templates = Jinja2Templates(directory="templates")

@router.get("/")
async def read_about(
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    return templates.TemplateResponse(
        "about.html", 
        {"request": request, "user": user}
    )