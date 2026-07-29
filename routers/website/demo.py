from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from utils.core.dependencies import get_optional_user
from utils.core.htmx import set_flash_cookie
from utils.core.models import User
from exceptions.http_exceptions import RateLimitError
from utils.core.rate_limit import check_website_lead_ip_rate_limit
from utils.website.content import website_demo_context
from utils.website.forms import BookDemoSubmission
from utils.website.notifications import notify_book_demo

router = APIRouter(tags=["website"])
templates = Jinja2Templates(directory="templates")


def _demo_template_context(
    request: Request,
    user: Optional[User],
    *,
    form_values: dict | None = None,
    form_errors: dict | None = None,
    form_error: str | None = None,
) -> dict:
    return {
        "request": request,
        "user": user,
        "form_values": form_values or {},
        "form_errors": form_errors or {},
        "form_error": form_error,
        **website_demo_context(),
    }


@router.get("/demo", name="read_demo")
async def read_demo(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
):
    """Public book-a-demo page."""
    return templates.TemplateResponse(
        request,
        "website/demo.html",
        _demo_template_context(request, user),
    )


@router.post("/demo", name="submit_book_demo")
async def submit_book_demo(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    work_email: str = Form(""),
    first_name: str = Form(""),
    last_name: str = Form(""),
    company: str = Form(""),
    trade: str = Form(""),
    phone: str = Form(""),
    technicians: str = Form(""),
    phone_answerer: str = Form(""),
):
    form_values = {
        "work_email": work_email,
        "first_name": first_name,
        "last_name": last_name,
        "company": company,
        "trade": trade,
        "phone": phone,
        "technicians": technicians,
        "phone_answerer": phone_answerer,
    }

    try:
        check_website_lead_ip_rate_limit(request)
    except RateLimitError:
        return templates.TemplateResponse(
            request,
            "website/demo.html",
            _demo_template_context(
                request,
                user,
                form_values=form_values,
                form_error="Too many requests. Please try again in a little while.",
            ),
            status_code=429,
        )

    submission, form_errors = BookDemoSubmission.from_form(**form_values)
    if submission is None:
        return templates.TemplateResponse(
            request,
            "website/demo.html",
            _demo_template_context(
                request,
                user,
                form_values=form_values,
                form_errors=form_errors,
            ),
            status_code=422,
        )

    notify_book_demo(submission)

    response = RedirectResponse(url=str(request.url_for("read_demo")), status_code=303)
    set_flash_cookie(
        response,
        "Thanks — we'll be in touch shortly to schedule your demo.",
        level="success",
    )
    return response
