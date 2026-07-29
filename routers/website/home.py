from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from utils.core.dependencies import get_optional_user
from utils.core.models import User
from utils.website.content import website_home_context

router = APIRouter(tags=["website"])
templates = Jinja2Templates(directory="templates")


@router.get("/", name="read_home")
async def read_home(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
):
    """Public Calliflowr website homepage."""
    context = {"user": user, **website_home_context()}
    return templates.TemplateResponse(
        request,
        "website/index.html",
        context,
    )
