from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates
from utils.core.dependencies import get_optional_user
from utils.core.models import User
from utils.website.content import website_home_context

router = APIRouter(tags=["static_pages"])
templates = Jinja2Templates(directory="templates")

# Define valid static pages to prevent arbitrary template access
VALID_PAGES = {
    "about": "static_pages/about.html",
    "blog": "static_pages/blog.html",
    "customers": "static_pages/customers.html",
    "privacy-policy": "static_pages/privacy_policy.html",
    "terms-and-conditions": "static_pages/terms_and_conditions.html",
    "website-fulfillment-policy": "static_pages/website_fulfillment_policy.html",
}

WEBSITE_THEMED_PAGES = {
    "about",
    "blog",
    "privacy-policy",
    "terms-and-conditions",
    "website-fulfillment-policy",
}


@router.get("/{page_name}", name="read_static_page")
async def read_static_page(
    page_name: str, request: Request, user: Optional[User] = Depends(get_optional_user)
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

    context: dict = {"user": user}
    if page_name in WEBSITE_THEMED_PAGES:
        context.update(website_home_context())

    return templates.TemplateResponse(request, VALID_PAGES[page_name], context)
