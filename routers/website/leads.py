from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from utils.core.dependencies import get_optional_user
from utils.core.htmx import set_flash_cookie
from utils.core.models import User
from exceptions.http_exceptions import RateLimitError
from utils.core.rate_limit import check_website_lead_ip_rate_limit
from utils.website.forms import CallMeSubmission
from utils.website.notifications import notify_call_me

router = APIRouter(tags=["website"])


@router.post("/call-me", name="submit_call_me")
async def submit_call_me(
    request: Request,
    name: str = Form(""),
    business: str = Form(""),
    email: str = Form(""),
    phone: str = Form(""),
    industry: str = Form(""),
    crm: str = Form(""),
    crm_other: str = Form(""),
    user: Optional[User] = Depends(get_optional_user),
):
    del user  # public endpoint; auth state does not affect submission

    form_values = {
        "name": name,
        "business": business,
        "email": email,
        "phone": phone,
        "industry": industry,
        "crm": crm,
        "crm_other": crm_other,
    }

    try:
        check_website_lead_ip_rate_limit(request)
    except RateLimitError:
        response = RedirectResponse(
            url=str(request.url_for("read_home")) + "#call-me",
            status_code=303,
        )
        set_flash_cookie(
            response,
            "Too many requests. Please try again in a little while.",
            level="danger",
        )
        return response

    submission, form_errors = CallMeSubmission.from_form(**form_values)
    if submission is None:
        first_error = next(iter(form_errors.values()), "Please check the form and try again.")
        response = RedirectResponse(
            url=str(request.url_for("read_home")) + "#call-me",
            status_code=303,
        )
        set_flash_cookie(response, first_error, level="danger")
        return response

    notify_call_me(submission)

    response = RedirectResponse(
        url=str(request.url_for("read_home")) + "#call-me",
        status_code=303,
    )
    set_flash_cookie(
        response,
        "Thanks — we'll have Calli ring you shortly.",
        level="success",
    )
    return response
