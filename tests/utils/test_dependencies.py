from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, UTC
from utils.core.models import EmailUpdateToken, Account, User, PasswordResetToken, Role
from utils.core.dependencies import (
    get_account_from_email_update_token, validate_token_and_get_account,
    get_account_from_credentials, get_account_from_tokens, get_authenticated_account,
    validate_token_and_get_user, get_user_from_tokens, get_authenticated_user,
    get_optional_user, get_account_from_reset_token, get_user_with_relations
)
from exceptions.http_exceptions import AuthenticationError, CredentialsError
from exceptions.exceptions import NeedsNewTokens
import pytest


def test_get_account_from_email_update_token() -> None:
    """
    Tests retrieving a user using an email update token.
    """
    session = MagicMock()

    # Test valid token
    mock_account = Account(id=1, email="test@example.com")
    mock_token = EmailUpdateToken(
        account_id=1,
        token="valid_token",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        used=False
    )
    session.exec.return_value.first.return_value = (mock_account, mock_token)

    account, token = get_account_from_email_update_token(1, "valid_token", session)
    assert account == mock_account
    assert token == mock_token

    # Test invalid token
    session.exec.return_value.first.return_value = None
    account, token = get_account_from_email_update_token(1, "invalid_token", session)
    assert account is None
    assert token is None


def test_validate_token_and_get_account() -> None:
    """
    Tests validating a token and retrieving the associated account.
    """
    session = MagicMock()
    mock_account = Account(id=1, email="test@example.com")
    session.exec.return_value.first.return_value = mock_account
    
    # Test with valid access token
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = {"sub": "test@example.com", "type": "access"}
        account, access_token, refresh_token = validate_token_and_get_account("valid_token", "access", session)
        assert account == mock_account
        assert access_token is None
        assert refresh_token is None
        mock_validate.assert_called_once_with("valid_token", token_type="access")
    
    # Test with valid refresh token
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        with patch('utils.core.dependencies.create_access_token') as mock_access_token:
            with patch('utils.core.dependencies.create_refresh_token') as mock_refresh_token:
                mock_validate.return_value = {"sub": "test@example.com", "type": "refresh"}
                mock_access_token.return_value = "new_access_token"
                mock_refresh_token.return_value = "new_refresh_token"
                
                account, access_token, refresh_token = validate_token_and_get_account("valid_token", "refresh", session)
                assert account == mock_account
                assert access_token == "new_access_token"
                assert refresh_token == "new_refresh_token"
                mock_validate.assert_called_once_with("valid_token", token_type="refresh")
                mock_access_token.assert_called_once_with(data={"sub": "test@example.com"})
                mock_refresh_token.assert_called_once_with(data={"sub": "test@example.com"})
    
    # Test with invalid token
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = None
        account, access_token, refresh_token = validate_token_and_get_account("invalid_token", "access", session)
        assert account is None
        assert access_token is None
        assert refresh_token is None
    
    # Test with valid token but no account found
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = {"sub": "nonexistent@example.com", "type": "access"}
        session.exec.return_value.first.return_value = None
        account, access_token, refresh_token = validate_token_and_get_account("valid_token", "access", session)
        assert account is None
        assert access_token is None
        assert refresh_token is None


def test_get_account_from_credentials() -> None:
    """
    Tests retrieving an account using credentials.
    """
    session = MagicMock()
    mock_account = Account(id=1, email="test@example.com", hashed_password="hashed_password")
    session.exec.return_value.first.return_value = mock_account
    
    # Test with valid credentials
    with patch('utils.core.dependencies.verify_password') as mock_verify:
        mock_verify.return_value = True
        account, returned_session = get_account_from_credentials("test@example.com", "password123", session)
        assert account == mock_account
        assert returned_session == session
        mock_verify.assert_called_once_with("password123", "hashed_password")
    
    # Test with invalid password
    with patch('utils.core.dependencies.verify_password') as mock_verify:
        mock_verify.return_value = False
        with pytest.raises(CredentialsError):
            get_account_from_credentials("test@example.com", "wrong_password", session)
    
    # Test with non-existent account
    session.exec.return_value.first.return_value = None
    with pytest.raises(CredentialsError):
        get_account_from_credentials("nonexistent@example.com", "password123", session)


def test_get_account_from_tokens() -> None:
    """
    Tests retrieving an account from tokens.
    """
    session = MagicMock()
    
    # Test with valid access token
    with patch('utils.core.dependencies.validate_token_and_get_account') as mock_validate:
        mock_account = Account(id=1, email="test@example.com")
        mock_validate.return_value = (mock_account, None, None)
        
        account, access_token, refresh_token = get_account_from_tokens(("valid_access", "valid_refresh"), session)
        assert account == mock_account
        assert access_token is None
        assert refresh_token is None
        mock_validate.assert_called_once_with("valid_access", "access", session)
    
    # Test with invalid access token but valid refresh token
    with patch('utils.core.dependencies.validate_token_and_get_account') as mock_validate:
        mock_account = Account(id=1, email="test@example.com")
        # First call returns None (invalid access token)
        # Second call returns account and new tokens (valid refresh token)
        mock_validate.side_effect = [
            (None, None, None),
            (mock_account, "new_access", "new_refresh")
        ]
        
        account, access_token, refresh_token = get_account_from_tokens(("invalid_access", "valid_refresh"), session)
        assert account == mock_account
        assert access_token == "new_access"
        assert refresh_token == "new_refresh"
        assert mock_validate.call_count == 2
    
    # Test with both tokens invalid
    with patch('utils.core.dependencies.validate_token_and_get_account') as mock_validate:
        mock_validate.return_value = (None, None, None)
        
        account, access_token, refresh_token = get_account_from_tokens(("invalid_access", "invalid_refresh"), session)
        assert account is None
        assert access_token is None
        assert refresh_token is None
        assert mock_validate.call_count == 2
    
    # Test with no tokens
    account, access_token, refresh_token = get_account_from_tokens((None, None), session)
    assert account is None
    assert access_token is None
    assert refresh_token is None


def test_get_authenticated_account() -> None:
    """
    Tests retrieving an authenticated account.
    """
    session = MagicMock()
    tokens = ("access_token", "refresh_token")
    
    # Test with valid account, no new tokens
    with patch('utils.core.dependencies.get_account_from_tokens') as mock_get_account:
        mock_account = Account(id=1, email="test@example.com")
        mock_get_account.return_value = (mock_account, None, None)
        
        account = get_authenticated_account(tokens, session)
        assert account == mock_account
    
    # Test with valid account, new tokens needed
    with patch('utils.core.dependencies.get_account_from_tokens') as mock_get_account:
        mock_account = Account(id=1, email="test@example.com", user=User(id=1, name="Test User"))
        mock_get_account.return_value = (mock_account, "new_access", "new_refresh")
        
        with pytest.raises(NeedsNewTokens) as exc_info:
            get_authenticated_account(tokens, session)
        
        assert exc_info.value.user == mock_account.user
        assert exc_info.value.access_token == "new_access"
        assert exc_info.value.refresh_token == "new_refresh"
    
    # Test with no valid account
    with patch('utils.core.dependencies.get_account_from_tokens') as mock_get_account:
        mock_get_account.return_value = (None, None, None)
        
        with pytest.raises(AuthenticationError):
            get_authenticated_account(tokens, session)


def test_validate_token_and_get_user() -> None:
    """
    Tests validating a token and retrieving the associated user.
    """
    session = MagicMock()
    mock_user = User(id=1, name="Test User")
    mock_account = Account(id=1, email="test@example.com", user=mock_user)
    session.exec.return_value.first.return_value = mock_account
    
    # Test with valid access token
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = {"sub": "test@example.com", "type": "access"}
        user, access_token, refresh_token = validate_token_and_get_user("valid_token", "access", session)
        assert user == mock_user
        assert access_token is None
        assert refresh_token is None
        mock_validate.assert_called_once_with("valid_token", token_type="access")
    
    # Test with valid refresh token
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        with patch('utils.core.dependencies.create_access_token') as mock_access_token:
            with patch('utils.core.dependencies.create_refresh_token') as mock_refresh_token:
                mock_validate.return_value = {"sub": "test@example.com", "type": "refresh"}
                mock_access_token.return_value = "new_access_token"
                mock_refresh_token.return_value = "new_refresh_token"
                
                user, access_token, refresh_token = validate_token_and_get_user("valid_token", "refresh", session)
                assert user == mock_user
                assert access_token == "new_access_token"
                assert refresh_token == "new_refresh_token"
                mock_validate.assert_called_once_with("valid_token", token_type="refresh")
                mock_access_token.assert_called_once_with(data={"sub": "test@example.com"})
                mock_refresh_token.assert_called_once_with(data={"sub": "test@example.com"})
    
    # Test with invalid token
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = None
        user, access_token, refresh_token = validate_token_and_get_user("invalid_token", "access", session)
        assert user is None
        assert access_token is None
        assert refresh_token is None
    
    # Test with valid token but no account found
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = {"sub": "nonexistent@example.com", "type": "access"}
        session.exec.return_value.first.return_value = None
        user, access_token, refresh_token = validate_token_and_get_user("valid_token", "access", session)
        assert user is None
        assert access_token is None
        assert refresh_token is None
    
    # Test with valid token and account but no user
    with patch('utils.core.dependencies.validate_token') as mock_validate:
        mock_validate.return_value = {"sub": "test@example.com", "type": "access"}
        mock_account_no_user = Account(id=1, email="test@example.com", user=None)
        session.exec.return_value.first.return_value = mock_account_no_user
        user, access_token, refresh_token = validate_token_and_get_user("valid_token", "access", session)
        assert user is None
        assert access_token is None
        assert refresh_token is None


def test_get_user_from_tokens() -> None:
    """
    Tests retrieving a user from tokens.
    """
    session = MagicMock()
    
    # Test with valid access token
    with patch('utils.core.dependencies.validate_token_and_get_user') as mock_validate:
        mock_user = User(id=1, name="Test User")
        mock_validate.return_value = (mock_user, None, None)
        
        user, access_token, refresh_token = get_user_from_tokens(("valid_access", "valid_refresh"), session)
        assert user == mock_user
        assert access_token is None
        assert refresh_token is None
        mock_validate.assert_called_once_with("valid_access", "access", session)
    
    # Test with invalid access token but valid refresh token
    with patch('utils.core.dependencies.validate_token_and_get_user') as mock_validate:
        mock_user = User(id=1, name="Test User")
        # First call returns None (invalid access token)
        # Second call returns user and new tokens (valid refresh token)
        mock_validate.side_effect = [
            (None, None, None),
            (mock_user, "new_access", "new_refresh")
        ]
        
        user, access_token, refresh_token = get_user_from_tokens(("invalid_access", "valid_refresh"), session)
        assert user == mock_user
        assert access_token == "new_access"
        assert refresh_token == "new_refresh"
        assert mock_validate.call_count == 2
    
    # Test with both tokens invalid
    with patch('utils.core.dependencies.validate_token_and_get_user') as mock_validate:
        mock_validate.return_value = (None, None, None)
        
        user, access_token, refresh_token = get_user_from_tokens(("invalid_access", "invalid_refresh"), session)
        assert user is None
        assert access_token is None
        assert refresh_token is None
        assert mock_validate.call_count == 2
    
    # Test with no tokens
    user, access_token, refresh_token = get_user_from_tokens((None, None), session)
    assert user is None
    assert access_token is None
    assert refresh_token is None


def test_get_authenticated_user() -> None:
    """
    Tests retrieving an authenticated user.
    """
    session = MagicMock()
    tokens = ("access_token", "refresh_token")
    
    # Test with valid user, no new tokens
    with patch('utils.core.dependencies.get_user_from_tokens') as mock_get_user:
        mock_user = User(id=1, name="Test User")
        mock_get_user.return_value = (mock_user, None, None)
        
        user = get_authenticated_user(tokens, session)
        assert user == mock_user
    
    # Test with valid user, new tokens needed
    with patch('utils.core.dependencies.get_user_from_tokens') as mock_get_user:
        mock_user = User(id=1, name="Test User")
        mock_get_user.return_value = (mock_user, "new_access", "new_refresh")
        
        with pytest.raises(NeedsNewTokens) as exc_info:
            get_authenticated_user(tokens, session)
        
        assert exc_info.value.user == mock_user
        assert exc_info.value.access_token == "new_access"
        assert exc_info.value.refresh_token == "new_refresh"
    
    # Test with no valid user
    with patch('utils.core.dependencies.get_user_from_tokens') as mock_get_user:
        mock_get_user.return_value = (None, None, None)
        
        with pytest.raises(AuthenticationError):
            get_authenticated_user(tokens, session)


def test_get_optional_user() -> None:
    """
    Tests retrieving an optional user.
    """
    session = MagicMock()
    tokens = ("access_token", "refresh_token")
    
    # Test with valid user, no new tokens
    with patch('utils.core.dependencies.get_user_from_tokens') as mock_get_user:
        mock_user = User(id=1, name="Test User")
        mock_get_user.return_value = (mock_user, None, None)
        
        user = get_optional_user(tokens, session)
        assert user == mock_user
    
    # Test with valid user, new tokens needed
    with patch('utils.core.dependencies.get_user_from_tokens') as mock_get_user:
        mock_user = User(id=1, name="Test User")
        mock_get_user.return_value = (mock_user, "new_access", "new_refresh")
        
        with pytest.raises(NeedsNewTokens) as exc_info:
            get_optional_user(tokens, session)
        
        assert exc_info.value.user == mock_user
        assert exc_info.value.access_token == "new_access"
        assert exc_info.value.refresh_token == "new_refresh"
    
    # Test with no valid user
    with patch('utils.core.dependencies.get_user_from_tokens') as mock_get_user:
        mock_get_user.return_value = (None, None, None)
        
        user = get_optional_user(tokens, session)
        assert user is None


def test_get_account_from_reset_token() -> None:
    """
    Tests retrieving an account from a password reset token.
    """
    session = MagicMock()

    # Test valid token
    mock_account = Account(id=1, email="test@example.com")
    mock_token = PasswordResetToken(
        account_id=1,
        token="valid_token",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        used=False
    )
    session.exec.return_value.first.return_value = (mock_account, mock_token)

    account, token = get_account_from_reset_token("test@example.com", "valid_token", session)
    assert account == mock_account
    assert token == mock_token

    # Test invalid token
    session.exec.return_value.first.return_value = None
    account, token = get_account_from_reset_token("test@example.com", "invalid_token", session)
    assert account is None
    assert token is None


def test_get_user_with_relations() -> None:
    """
    Tests retrieving a user with loaded relationships.
    """
    session = MagicMock()
    mock_user = User(id=1, name="Test User")
    
    # Create a mock user with loaded relationships
    mock_eager_user = User(
        id=1, 
        name="Test User",
        roles=[
            Role(id=1, name="Admin", organization_id=1)
        ]
    )
    
    session.exec.return_value.one.return_value = mock_eager_user
    
    # Test getting user with relations
    user = get_user_with_relations(mock_user, session)
    assert user == mock_eager_user
    
    # Verify the query was constructed correctly
    session.exec.assert_called_once()
    # We can't easily check the exact query construction with selectinload,
    # but we can verify the where clause was applied correctly
    assert '"user".id' in str(session.exec.call_args[0][0])
    assert 'id_1' in str(session.exec.call_args[0][0])