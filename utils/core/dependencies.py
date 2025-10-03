from fastapi import Depends, Form
from pydantic import EmailStr
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from datetime import UTC, datetime
from typing import Optional, Tuple, Generator
from utils.core.auth import (
    validate_token, create_access_token, create_refresh_token,
    oauth2_scheme_cookie, verify_password
)
from utils.core.db import create_engine, get_connection_url
from utils.core.models import User, Role, PasswordResetToken, EmailUpdateToken, Account
from exceptions.http_exceptions import AuthenticationError, CredentialsError, DataIntegrityError
from exceptions.exceptions import NeedsNewTokens


def get_session() -> Generator[Session, None, None]:
    """
    Provides a database session for executing queries.

    Yields:
        Session: A SQLModel session object for database operations.
    """
    engine = create_engine(get_connection_url())
    with Session(engine) as session:
        yield session


def validate_token_and_get_account(
    token: str,
    token_type: str,
    session: Session
) -> tuple[Optional[Account], Optional[str], Optional[str]]:
    """
    Validates a token and returns the associated account if valid.
    
    Args:
        token: JWT token to validate
        token_type: Type of token ('access' or 'refresh')
        session: Database session
        
    Returns:
        Tuple containing the account (if valid), and new tokens (if refresh token)
    """
    decoded_token = validate_token(token, token_type=token_type)
    
    if decoded_token:
        user_email = decoded_token.get("sub")
        account = session.exec(select(Account).where(
            Account.email == user_email
        )).first()
        
        if account:
            if token_type == "refresh":
                new_access_token = create_access_token(
                    data={"sub": account.email})
                new_refresh_token = create_refresh_token(
                    data={"sub": account.email})
                return account, new_access_token, new_refresh_token
            return account, None, None
    return None, None, None


def get_account_from_credentials(
    email: EmailStr = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session)
) -> Tuple[Account, Session]:
    """
    Validates user credentials and returns the account if valid.

    Args:
        email: Email address from form
        password: Password from form
        session: Database session

    Returns:
        Tuple containing the account and session

    Raises:
        HTTPException: If credentials are invalid
    """
    account = session.exec(select(Account).where(
        Account.email == email)).first()
    
    if not account or not verify_password(password, account.hashed_password):
        raise CredentialsError()

    return account, session


def get_account_from_tokens(
    tokens: tuple[Optional[str], Optional[str]],
    session: Session
) -> tuple[Optional[Account], Optional[str], Optional[str]]:
    """
    Attempts to get an account from access or refresh tokens.
    
    Args:
        tokens: Tuple of (access_token, refresh_token)
        session: Database session
        
    Returns:
        Tuple containing the account (if valid), and new tokens (if using refresh token)
    """
    access_token, refresh_token = tokens

    # Try to validate the access token first
    account, _, _ = validate_token_and_get_account(
        access_token, "access", session) if access_token else (None, None, None)
    if account:
        return account, None, None

    # If access token is invalid or missing, try the refresh token
    if refresh_token:
        account, new_access_token, new_refresh_token = validate_token_and_get_account(
            refresh_token, "refresh", session)
        if account:
            return account, new_access_token, new_refresh_token

    # Return a tuple of None values if no valid account is found
    return None, None, None


def get_authenticated_account(
    tokens: tuple[Optional[str], Optional[str]] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
) -> Account:
    """
    Dependency that returns the authenticated account or raises an exception.
    
    Args:
        tokens: Tuple of (access_token, refresh_token)
        session: Database session
        
    Returns:
        The authenticated account
        
    Raises:
        AuthenticationError: If no valid account is found
        NeedsNewTokens: If using refresh token and new tokens are generated
    """
    account, new_access_token, new_refresh_token = get_account_from_tokens(
        tokens, session)

    if account:
        if new_access_token and new_refresh_token:
            # This will be caught by middleware to set new cookies
            if account.user:
                raise NeedsNewTokens(account.user, new_access_token, new_refresh_token)
            else:
                raise   DataIntegrityError("User")
        return account

    raise AuthenticationError()


def validate_token_and_get_user(
    token: str,
    token_type: str,
    session: Session
) -> tuple[Optional[User], Optional[str], Optional[str]]:
    decoded_token = validate_token(token, token_type=token_type)

    if decoded_token:
        user_email = decoded_token.get("sub")
        account = session.exec(select(Account).where(
            Account.email == user_email
        )).first()
        
        if account and account.user:
            if token_type == "refresh":
                new_access_token = create_access_token(
                    data={"sub": account.email})
                new_refresh_token = create_refresh_token(
                    data={"sub": account.email})
                return account.user, new_access_token, new_refresh_token
            return account.user, None, None
    return None, None, None


def get_user_from_tokens(
    tokens: tuple[Optional[str], Optional[str]],
    session: Session
) -> tuple[Optional[User], Optional[str], Optional[str]]:
    access_token, refresh_token = tokens

    # Try to validate the access token first
    user, _, _ = validate_token_and_get_user(
        access_token, "access", session) if access_token else (None, None, None)
    if user:
        return user, None, None

    # If access token is invalid or missing, try the refresh token
    if refresh_token:
        user, new_access_token, new_refresh_token = validate_token_and_get_user(
            refresh_token, "refresh", session)
        if user:
            return user, new_access_token, new_refresh_token

    # Return a tuple of None values if no valid user is found
    return None, None, None


def get_authenticated_user(
    tokens: tuple[Optional[str], Optional[str]
                  ] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
) -> User:
    user, new_access_token, new_refresh_token = get_user_from_tokens(
        tokens, session)

    if user:
        if new_access_token and new_refresh_token:
            raise NeedsNewTokens(user, new_access_token, new_refresh_token)
        return user

    raise AuthenticationError()


# TODO: Maybe instead of an optional function, we have get_account and then
# get_required_account, which just wraps it?
def get_optional_user(
    tokens: tuple[Optional[str], Optional[str]
                  ] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session)
) -> Optional[User]:
    user, new_access_token, new_refresh_token = get_user_from_tokens(
        tokens, session)

    if user:
        if new_access_token and new_refresh_token:
            raise NeedsNewTokens(user, new_access_token, new_refresh_token)
        return user

    return None


def get_account_from_email_update_token(
    account_id: int,
    token: str,
    session: Session
) -> tuple[Optional[Account], Optional[EmailUpdateToken]]:
    """
    Get account from an email update token.
    
    Args:
        account_id: ID of the account
        token: Email update token
        session: Database session
        
    Returns:
        Tuple of (account, token) if valid, or (None, None) if invalid
    """
    result = session.exec(
        select(Account, EmailUpdateToken)
        .where(
            Account.id == account_id,
            EmailUpdateToken.token == token,
            EmailUpdateToken.expires_at > datetime.now(UTC),
            EmailUpdateToken.used == False,
            EmailUpdateToken.account_id == Account.id
        )
    ).first()

    if not result:
        return None, None

    account, update_token = result
    return account, update_token


def get_account_from_reset_token(
    email: str, 
    token: str, 
    session: Session
) -> tuple[Optional[Account], Optional[PasswordResetToken]]:
    """
    Get account from a password reset token.
    
    Args:
        email: Email address of the account
        token: Password reset token
        session: Database session
        
    Returns:
        Tuple of (account, token) if valid, or (None, None) if invalid
    """
    result = session.exec(
        select(Account, PasswordResetToken)
        .where(
            Account.email == email,
            PasswordResetToken.token == token,
            PasswordResetToken.expires_at > datetime.now(UTC),
            PasswordResetToken.used == False,
            PasswordResetToken.account_id == Account.id
        )
    ).first()

    if not result:
        return None, None

    account, reset_token = result
    return account, reset_token


def get_user_with_relations(
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
) -> User:
    """
    Returns an authenticated user with fully loaded role and organization relationships.
    """
    # Refresh the user instance with eagerly loaded relationships
    eager_user = session.exec(
        select(User)
        .where(User.id == user.id)
        .options(
            selectinload(User.roles).selectinload(Role.organization),
            selectinload(User.roles).selectinload(Role.permissions)
        )
    ).one()

    return eager_user