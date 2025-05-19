from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates
from utils.core.dependencies import get_optional_user
from utils.core.models import User

router = APIRouter(tags=["static_pages"])
templates = Jinja2Templates(directory="templates")

# Define valid static pages to prevent arbitrary template access
VALID_PAGES = {
    "about": "static_pages/about.html",
    "privacy-policy": "static_pages/privacy_policy.html",
    "terms-of-service": "static_pages/terms_of_service.html"
}

@router.get("/{page_name}", name="read_static_page")
async def read_static_page(
    page_name: str,
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    """
    Generic handler for static pages.
    
    Args:
        page_name: The name of the page to render (must be in VALID_PAGES).
        request: The FastAPI request object.
        user: The optional authenticated user.
        
    Returns:
        TemplateResponse for the requested page.
        
    Raises:
        HTTPException: If the page_name is not in VALID_PAGES.
    """
    if page_name not in VALID_PAGES:
        raise HTTPException(status_code=404, detail="Page not found")
        
    return templates.TemplateResponse(
        request,
        VALID_PAGES[page_name],
        {"user": user}
    ) 