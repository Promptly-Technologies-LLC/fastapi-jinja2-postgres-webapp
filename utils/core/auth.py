# utils.core.py
import os
import re
import jwt
import uuid
import logging
import resend
from sqlmodel import Session, select
from bcrypt import gensalt, hashpw, checkpw
from datetime import UTC, datetime, timedelta
from typing import Optional
from jinja2.environment import Template
from fastapi.templating import Jinja2Templates
from fastapi import Cookie
from utils.core.db import create_engine, get_connection_url
from utils.core.models import AccountEmail, AccountRecoveryToken, EmailVerificationToken, PasswordResetToken, RefreshToken, Account

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


# --- Constants ---


templates = Jinja2Templates(directory="templates")
COOKIE_SECURE = os.getenv("BASE_URL", "http://localhost:8000").startswith("https")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30
PASSWORD_PATTERN_COMPONENTS = [
    r"(?=.*\d)",                   # At least one digit
    r"(?=.*[a-z])",               # At least one lowercase letter
    r"(?=.*[A-Z])",               # At least one uppercase letter
    r"(?=.*[\[\]\\@$!%*?&{}<>.,'#\-_=+\(\):;|~/\^])",  # At least one special character
    r".{8,}"  # At least 8 characters long
]
COMPILED_PASSWORD_PATTERN = re.compile(r"".join(PASSWORD_PATTERN_COMPONENTS))


def convert_python_regex_to_html(regex: str) -> str:
    """
    Replace each special character with its escaped version only when inside character classes.
    Ensures that the single quote "'" is doubly escaped.
    """
    # Map each special char to its escaped form
    special_map = {
        '{': r'\{',
        '}': r'\}',
        '<': r'\<',
        '>': r'\>',
        '.': r'\.',
        '+': r'\+',
        '|': r'\|',
        ',': r'\,',
        "'": r"\\'",  # doubly escaped single quote
        "/": r"\/",
    }

    # Regex to match the entire character class [ ... ]
    pattern = r"\[((?:\\.|[^\]])*)\]"

    def replacer(match: re.Match) -> str:
        """
        For the matched character class, replace all special characters inside it.
        """
        inside = match.group(1)  # the contents inside [ ... ]
        for ch, escaped in special_map.items():
            inside = inside.replace(ch, escaped)
        return f"[{inside}]"

    # Use re.sub with a function to ensure we only replace inside the character class
    return re.sub(pattern, replacer, regex)


HTML_PASSWORD_PATTERN = "".join(
    convert_python_regex_to_html(component) for component in PASSWORD_PATTERN_COMPONENTS
)


# --- Helpers ---


# Define the oauth2 scheme to get the token from the cookie
def oauth2_scheme_cookie(
    access_token: Optional[str] = Cookie(None, alias="access_token"),
    refresh_token: Optional[str] = Cookie(None, alias="refresh_token"),
) -> tuple[Optional[str], Optional[str]]:
    return access_token, refresh_token


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt with a random salt
    """
    # Convert the password to bytes and generate the hash
    password_bytes = password.encode('utf-8')
    salt = gensalt()
    return hashpw(password_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a bcrypt hash
    """
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return checkpw(password_bytes, hashed_bytes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.update({"type": "access"})
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(
            UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, jti: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.update({"type": "refresh", "jti": jti})
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)
    return encoded_jwt


def create_tracked_refresh_token(account_id: int, email: str, session: Session) -> str:
    jti = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    db_token = RefreshToken(
        account_id=account_id,
        jti=jti,
        expires_at=expires_at,
    )
    session.add(db_token)
    token = create_refresh_token(data={"sub": email}, jti=jti)
    return token


def revoke_all_refresh_tokens(account_id: int, session: Session) -> None:
    tokens = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == account_id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    for token in tokens:
        token.revoked = True


def cleanup_expired_refresh_tokens(session: Session) -> int:
    expired = session.exec(
        select(RefreshToken).where(RefreshToken.expires_at < datetime.now(UTC))
    ).all()
    count = len(expired)
    for token in expired:
        session.delete(token)
    session.commit()
    return count


def validate_token(token: str, token_type: str = "access") -> Optional[dict]:
    try:
        decoded_token = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[ALGORITHM])

        # Check if the token has expired
        if decoded_token["exp"] < datetime.now(UTC).timestamp():
            return None

        # Optional: Add additional checks specific to each token type
        if token_type == "refresh" and "refresh" not in decoded_token.get("type", ""):
            return None
        elif token_type == "access" and "access" not in decoded_token.get("type", ""):
            return None

        return decoded_token
    except jwt.PyJWTError:
        return None


def generate_password_reset_url(email: str, token: str) -> str:
    """
    Generates the password reset URL with proper query parameters.

    Args:
        email: User's email address
        token: Password reset token

    Returns:
        Complete password reset URL
    """
    base_url = os.getenv('BASE_URL')
    return f"{base_url}/account/reset_password?email={email}&token={token}"


def send_reset_email(email: str, session: Session) -> None:
    # Check for an existing unexpired token
    account: Optional[Account] = session.exec(select(Account).where(
        Account.email == email
    )).first()
    
    if account:
        existing_token = session.exec(
            select(PasswordResetToken)
            .where(
                PasswordResetToken.account_id == account.id,
                PasswordResetToken.expires_at > datetime.now(UTC),
                PasswordResetToken.used == False  # noqa: E712 - SQL expression for boolean false
            )
        ).first()

        if existing_token:
            logger.debug("An unexpired token already exists for this account.")
            return

        # Generate a new token
        token: str = str(uuid.uuid4())
        reset_token: PasswordResetToken = PasswordResetToken(
            account_id=account.id, token=token)
        session.add(reset_token)

        try:
            reset_url: str = generate_password_reset_url(email, token)

            # Render the email template
            template: Template = templates.get_template(
                "emails/reset_email.html")
            html_content: str = template.render({"reset_url": reset_url})

            resend.api_key = os.getenv("RESEND_API_KEY")
            params = {
                "from": os.getenv("EMAIL_FROM", ""),
                "to": [email],
                "subject": "Password Reset Request",
                "html": html_content,
            }

            sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
            logger.debug(f"Password reset email sent: {sent_email.get('id')}")

            session.commit()
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            session.rollback()
    else:
        logger.debug("No account found with the provided email.")


def send_reset_email_task(email: str) -> None:
    """
    Background-task wrapper that creates its own session.

    FastAPI background tasks should not reuse request-scoped resources from
    `yield` dependencies, because cleanup may run before the task executes.
    """
    engine = create_engine(get_connection_url())
    with Session(engine) as session:
        send_reset_email(email, session)


# --- Multi-email functions ---


MAX_EMAILS_PER_ACCOUNT = 2


def generate_email_verification_url(token: str) -> str:
    """Generates the email verification URL."""
    base_url = os.getenv('BASE_URL')
    return f"{base_url}/account/emails/verify?token={token}"


def send_email_verification(account_id: int, new_email: str, session: Session) -> bool:
    """
    Send a verification email for adding a new email address.
    Returns True if email was sent, False if suppressed (existing unexpired token).
    """
    # Check for existing unexpired token for this account+email
    existing_token = session.exec(
        select(EmailVerificationToken)
        .where(
            EmailVerificationToken.account_id == account_id,
            EmailVerificationToken.new_email == new_email,
            EmailVerificationToken.expires_at > datetime.now(UTC),
            EmailVerificationToken.used == False  # noqa: E712
        )
    ).first()

    if existing_token:
        logger.debug("An unexpired verification token already exists for this email.")
        return False

    # Create new token
    token = EmailVerificationToken(
        account_id=account_id,
        new_email=new_email,
    )
    session.add(token)

    try:
        verification_url = generate_email_verification_url(token.token)

        template: Template = templates.get_template("emails/verify_new_email.html")
        html_content: str = template.render({"verification_url": verification_url})

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [new_email],
            "subject": "Verify Your Email Address",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Email verification sent: {sent_email.get('id')}")

        session.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to send email verification: {e}")
        session.rollback()
        return False


def send_email_verified_notification(primary_email: str, new_email: str) -> None:
    """Send a notification to the primary email that a new email was verified."""
    try:
        template: Template = templates.get_template("emails/email_verified_alert.html")
        html_content: str = template.render({"new_email": new_email})

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [primary_email],
            "subject": "New Email Address Added to Your Account",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Email verified notification sent: {sent_email.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send email verified notification: {e}")


def send_primary_email_changed_notification(old_email: str, new_email: str, recovery_url: str) -> None:
    """Send a notification to the old primary email that primary was changed."""
    try:
        template: Template = templates.get_template("emails/primary_email_changed.html")
        html_content: str = template.render({
            "old_email": old_email,
            "new_email": new_email,
            "recovery_url": recovery_url,
        })

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [old_email],
            "subject": "Your Primary Email Has Been Changed",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Primary email changed notification sent: {sent_email.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send primary email changed notification: {e}")


def send_email_removed_notification(removed_email: str, recovery_url: str) -> None:
    """Send a notification to the removed email address."""
    try:
        template: Template = templates.get_template("emails/email_removed_alert.html")
        html_content: str = template.render({
            "removed_email": removed_email,
            "recovery_url": recovery_url,
        })

        resend.api_key = os.getenv("RESEND_API_KEY")
        params = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [removed_email],
            "subject": "Email Address Removed from Your Account",
            "html": html_content,
        }

        sent_email = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.debug(f"Email removed notification sent: {sent_email.get('id')}")
    except Exception as e:
        logger.error(f"Failed to send email removed notification: {e}")


# --- Account recovery functions ---


def generate_recovery_url(token: str) -> str:
    """Generates the account recovery URL."""
    base_url = os.getenv('BASE_URL')
    return f"{base_url}/account/recover?token={token}"


def create_recovery_token(account_id: int, email: str, session: Session) -> str:
    """
    Create an account recovery token for the given email.
    Returns the token string. Does NOT commit — caller is responsible.
    If an unexpired token already exists for the same account+email, returns it.
    """
    existing = session.exec(
        select(AccountRecoveryToken)
        .where(
            AccountRecoveryToken.account_id == account_id,
            AccountRecoveryToken.email == email,
            AccountRecoveryToken.expires_at > datetime.now(UTC),
            AccountRecoveryToken.used == False,  # noqa: E712
        )
    ).first()

    if existing:
        return existing.token

    token = AccountRecoveryToken(
        account_id=account_id,
        email=email,
    )
    session.add(token)
    return token.token
