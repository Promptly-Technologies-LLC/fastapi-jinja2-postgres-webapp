from fastapi.testclient import TestClient
from httpx import Response
from sqlmodel import Session
from unittest.mock import patch
from typing import cast

from main import app
from utils.models import User
from utils.images import InvalidImageError

# Mock data for consistent testing
MOCK_IMAGE_DATA = b"processed fake image data"
MOCK_CONTENT_TYPE = "image/png"


def test_read_profile_unauthorized(unauth_client: TestClient):
    """Test that unauthorized users cannot view profile"""
    response = unauth_client.get(app.url_path_for(
        "read_profile"), follow_redirects=False)
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


def test_read_profile_authorized(auth_client: TestClient, test_user: User):
    """Test that authorized users can view their profile"""
    response = auth_client.get(app.url_path_for("read_profile"))
    assert response.status_code == 200
    
    # Get the response text
    response_text = response.text
    
    # Verify account exists
    assert test_user.account is not None
    
    # Verify email is in the response if it exists
    if test_user.account.email is not None:
        assert response_text.find(str(test_user.account.email)) != -1
    
    # Verify name is in the response if it exists
    if test_user.name is not None:
        assert response_text.find(str(test_user.name)) != -1


def test_update_profile_unauthorized(unauth_client: TestClient):
    """Test that unauthorized users cannot edit profile"""
    response: Response = unauth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "New Name"
        },
        files={
            "avatar_file": ("test_avatar.jpg", b"fake image data", "image/jpeg")
        },
        follow_redirects=False
    )
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


@patch('routers.user.validate_and_process_image')
def test_update_profile_authorized(mock_validate, auth_client: TestClient, test_user: User, session: Session):
    """Test that authorized users can edit their profile"""
    
    # Configure mock to return processed image data
    mock_validate.return_value = (MOCK_IMAGE_DATA, MOCK_CONTENT_TYPE)
    
    # Update profile
    response: Response = auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "Updated Name"
        },
        files={
            "avatar_file": ("test_avatar.jpg", b"fake image data", "image/jpeg")
        },
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_profile")

    # Verify changes in database
    session.refresh(test_user)
    assert test_user.name == "Updated Name"
    assert test_user.avatar_data == MOCK_IMAGE_DATA
    assert test_user.avatar_content_type == MOCK_CONTENT_TYPE

    # Verify mock was called correctly
    mock_validate.assert_called_once()


def test_update_profile_without_avatar(auth_client: TestClient, test_user: User, session: Session):
    """Test that profile can be updated without changing the avatar"""
    response: Response = auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "Updated Name"
        },
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_profile")

    # Verify changes in database
    session.refresh(test_user)
    assert test_user.name == "Updated Name"


def test_delete_account_unauthorized(unauth_client: TestClient):
    """Test that unauthorized users cannot delete account"""
    response: Response = unauth_client.post(
        app.url_path_for("delete_account"),
        data={"confirm_delete_password": "Test123!@#"},
        follow_redirects=False
    )
    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == app.url_path_for("read_login")


def test_delete_account_wrong_password(auth_client: TestClient, test_user: User):
    """Test that account deletion fails with wrong password"""
    response: Response = auth_client.post(
        app.url_path_for("delete_account"),
        data={
            "email": test_user.account.email if test_user.account else "",
            "password": "WrongPassword123!"
        },
        follow_redirects=False
    )
    assert response.status_code == 422
    assert "Password is incorrect" in response.text.strip()


def test_delete_account_success(auth_client: TestClient, test_user: User, session: Session):
    """Test successful account deletion"""

    # Store the user ID for later verification
    user_id = test_user.id

    # Delete account
    response: Response = auth_client.post(
        app.url_path_for("delete_account"),
        data={
            "email": test_user.account.email if test_user.account else "",
            "password": "Test123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("logout")

    # Clear the session and query for the user again to ensure we're not using a cached object
    session.close()
    session.expire_all()
    
    # Verify user is deleted from database
    user = session.get(User, user_id)
    assert user is None


@patch('routers.user.validate_and_process_image')
def test_get_avatar_authorized(mock_validate, auth_client: TestClient, test_user: User):
    """Test getting user avatar"""
    # Configure mock to return processed image data
    mock_validate.return_value = (MOCK_IMAGE_DATA, MOCK_CONTENT_TYPE)

    # First upload an avatar
    auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": test_user.name or ""  # Ensure name is not None
        },
        files={
            "avatar_file": ("test_avatar.jpg", b"fake image data", "image/jpeg")
        },
    )

    # Then try to retrieve it
    response = auth_client.get(
        app.url_path_for("get_avatar")
    )
    assert response.status_code == 200
    assert response.content == MOCK_IMAGE_DATA
    assert response.headers["content-type"] == MOCK_CONTENT_TYPE


def test_get_avatar_unauthorized(unauth_client: TestClient):
    """Test getting avatar for non-existent user"""
    response = unauth_client.get(
        app.url_path_for("get_avatar"),
        follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == app.url_path_for("read_login")


# Add new test for invalid image
@patch('routers.user.validate_and_process_image')
def test_update_profile_invalid_image(mock_validate, auth_client: TestClient):
    """Test that invalid images are rejected"""
    # Configure mock to raise InvalidImageError
    mock_validate.side_effect = InvalidImageError("Invalid test image")
    
    response: Response = auth_client.post(
        app.url_path_for("update_profile"),
        data={
            "name": "Updated Name"
        },
        files={
            "avatar_file": ("test_avatar.jpg", b"invalid image data", "image/jpeg")
        },
    )
    assert response.status_code == 400
    assert "Invalid test image" in response.text
