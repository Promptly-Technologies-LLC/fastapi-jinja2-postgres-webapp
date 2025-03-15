from fastapi import APIRouter, Depends, Form, UploadFile, File, Request
from fastapi.responses import RedirectResponse, Response
from sqlmodel import Session
from typing import Optional
from fastapi.templating import Jinja2Templates
from utils.models import User, DataIntegrityError
from utils.db import get_session
from utils.dependencies import get_authenticated_user
from utils.images import validate_and_process_image, MAX_FILE_SIZE, MIN_DIMENSION, MAX_DIMENSION, ALLOWED_CONTENT_TYPES

router = APIRouter(prefix="/user", tags=["user"])
templates = Jinja2Templates(directory="templates")


# --- Routes ---


@router.get("/profile")
async def read_profile(
    request: Request,
    user: User = Depends(get_authenticated_user),
    email_update_requested: Optional[str] = "false",
    email_updated: Optional[str] = "false"
):
    # Add image constraints to the template context
    return templates.TemplateResponse(
        request,
        "users/profile.html", {
            "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),  # Convert bytes to MB
            "min_dimension": MIN_DIMENSION,
            "max_dimension": MAX_DIMENSION,
            "allowed_formats": list(ALLOWED_CONTENT_TYPES.keys()),
            "email_update_requested": email_update_requested,
            "email_updated": email_updated,
            "user": user
        }
    )


@router.post("/update", response_class=RedirectResponse)
async def update_profile(
    name: Optional[str] = Form(None),
    avatar_file: Optional[UploadFile] = File(None),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Handle avatar update
    if avatar_file:
        avatar_data = await avatar_file.read()
        avatar_content_type = avatar_file.content_type
        
        processed_image, content_type = validate_and_process_image(
            avatar_data,
            avatar_content_type
        )
        user.avatar_data = processed_image
        user.avatar_content_type = content_type

    # Update user details
    user.name = name

    session.commit()
    session.refresh(user)
    return RedirectResponse(url=router.url_path_for("read_profile"), status_code=303)


@router.get("/avatar")
async def get_avatar(
    user: User = Depends(get_authenticated_user)
):
    """Serve avatar image from database"""
    if not user.avatar_data:
        raise DataIntegrityError(
            resource="User avatar"
        )

    return Response(
        content=user.avatar_data,
        media_type=user.avatar_content_type
    )
