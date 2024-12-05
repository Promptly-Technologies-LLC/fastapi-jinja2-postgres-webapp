from fastapi import APIRouter, Depends, HTTPException, Form, UploadFile, File
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select
from typing import Optional
from utils.models import User
from utils.auth import get_session, get_authenticated_user, verify_password

router = APIRouter(prefix="/user", tags=["user"])


# -- Server Request and Response Models --


class UpdateProfile(BaseModel):
    """Request model for updating user profile information"""
    name: str
    email: EmailStr
    avatar_url: Optional[str] = None
    avatar_file: Optional[bytes] = None
    avatar_content_type: Optional[str] = None

    @classmethod
    async def as_form(
        cls,
        name: str = Form(...),
        email: EmailStr = Form(...),
        avatar_url: Optional[str] = Form(None),
        avatar_file: Optional[UploadFile] = File(None),
    ):
        avatar_data = None
        avatar_content_type = None

        if avatar_file:
            # Read the file content
            avatar_data = await avatar_file.read()
            avatar_content_type = avatar_file.content_type

        return cls(
            name=name,
            email=email,
            avatar_url=avatar_url if not avatar_file else None,
            avatar_file=avatar_data,
            avatar_content_type=avatar_content_type
        )


class UserDeleteAccount(BaseModel):
    confirm_delete_password: str

    @classmethod
    async def as_form(
        cls,
        confirm_delete_password: str = Form(...),
    ):
        return cls(confirm_delete_password=confirm_delete_password)


# -- Routes --


@router.post("/update_profile", response_class=RedirectResponse)
async def update_profile(
    user_profile: UpdateProfile = Depends(UpdateProfile.as_form),
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Update user details
    current_user.name = user_profile.name
    current_user.email = user_profile.email

    # Handle avatar update
    if user_profile.avatar_file:
        current_user.avatar_url = None
        current_user.avatar_data = user_profile.avatar_file
        current_user.avatar_content_type = user_profile.avatar_content_type
    else:
        current_user.avatar_url = user_profile.avatar_url
        current_user.avatar_data = None
        current_user.avatar_content_type = None

    session.commit()
    session.refresh(current_user)
    return RedirectResponse(url="/profile", status_code=303)


@router.post("/delete_account", response_class=RedirectResponse)
async def delete_account(
    user_delete_account: UserDeleteAccount = Depends(
        UserDeleteAccount.as_form),
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    if not current_user.password:
        raise HTTPException(
            status_code=500,
            detail="User password not found in database; please contact a system administrator"
        )

    if not verify_password(
        user_delete_account.confirm_delete_password,
        current_user.password.hashed_password
    ):
        raise HTTPException(
            status_code=400,
            detail="Password is incorrect"
        )

    # Delete the user
    session.delete(current_user)
    session.commit()

    # Log out the user
    return RedirectResponse(url="/auth/logout", status_code=303)


@router.get("/avatar/{user_id}")
async def get_avatar(
    user_id: int,
    session: Session = Depends(get_session)
):
    """Serve avatar image from database"""
    user = session.exec(select(User).where(User.id == user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.avatar_data:
        return Response(
            content=user.avatar_data,
            media_type=user.avatar_content_type
        )
    elif user.avatar_url:
        return RedirectResponse(url=user.avatar_url)
    else:
        raise HTTPException(status_code=404, detail="Avatar not found")
