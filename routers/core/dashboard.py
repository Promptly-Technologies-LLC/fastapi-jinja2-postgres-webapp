from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Response
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from utils.core.dependencies import get_user_with_relations, get_session
from utils.core.models import User, Organization
from utils.app.enums import AppPermissions
from utils.app.models import OrganizationResource

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
templates = Jinja2Templates(directory="templates")


# --- Authenticated Routes ---


@router.get("/")
async def read_dashboard(
    request: Request,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session),
):
    organizations = user.organizations
    selected_org: Optional[Organization] = None
    resources: List[OrganizationResource] = []
    can_read = False
    can_write = False
    can_delete = False

    if organizations:
        # Read selected org from cookie, fall back to first org
        selected_org_id_str = request.cookies.get("selected_organization_id")
        if selected_org_id_str:
            try:
                selected_org_id = int(selected_org_id_str)
                selected_org = next(
                    (o for o in organizations if o.id == selected_org_id), None
                )
            except ValueError:
                pass

        if not selected_org:
            selected_org = organizations[0]

        # Load organization resources for the selected org
        if selected_org and selected_org.id is not None:
            resources = list(session.exec(
                select(OrganizationResource)
                .where(OrganizationResource.organization_id == selected_org.id)
                .order_by(OrganizationResource.created_at.desc())  # type: ignore[union-attr]
            ).all())
            can_read = user.has_permission(
                AppPermissions.READ_ORGANIZATION_RESOURCES, selected_org
            )
            can_write = user.has_permission(
                AppPermissions.WRITE_ORGANIZATION_RESOURCES, selected_org
            )
            can_delete = user.has_permission(
                AppPermissions.DELETE_ORGANIZATION_RESOURCES, selected_org
            )

    return templates.TemplateResponse(
        request,
        "dashboard/index.html",
        {
            "user": user,
            "organizations": organizations,
            "selected_org": selected_org,
            "resources": resources,
            "can_read": can_read,
            "can_write": can_write,
            "can_delete": can_delete,
        }
    )


@router.post("/select-organization/{org_id}")
async def select_organization(
    request: Request,
    org_id: int,
    user: User = Depends(get_user_with_relations),
):
    """Set the selected organization cookie and redirect back to dashboard."""
    # Verify user is a member of this organization
    org = next((o for o in user.organizations if o.id == org_id), None)
    if not org:
        # Fall back to dashboard without changing cookie
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = str(request.url_for("read_dashboard"))
        return response

    response = Response(status_code=200)
    response.set_cookie(
        key="selected_organization_id",
        value=str(org_id),
        httponly=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 365,  # 1 year
    )
    response.headers["HX-Redirect"] = str(request.url_for("read_dashboard"))
    return response
