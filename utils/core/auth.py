# utils.core.py
import os
import re
import jwt
import uuid
import logging
import resend
from dotenv import load_dotenv
from sqlmodel import Session, select
from bcrypt import gensalt, hashpw, checkpw
from datetime import UTC, datetime, timedelta
from typing import Optional
from jinja2.environment import Template
from fastapi.templating import Jinja2Templates
from fastapi import Cookie
from utils.core.models import PasswordResetToken, EmailUpdateToken, Account

load_dotenv(override=True)
resend.api_key = os.environ["RESEND_API_KEY"]

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


# --- Constants ---


templates = Jinja2Templates(directory="templates")
SECRET_KEY = os.getenv("SECRET_KEY")
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
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.update({"type": "refresh"})
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def validate_token(token: str, token_type: str = "access") -> Optional[dict]:
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

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
                PasswordResetToken.used == False
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

            params: resend.Emails.SendParams = {
                "from": os.getenv("EMAIL_FROM", ""),
                "to": [email],
                "subject": "Password Reset Request",
                "html": html_content,
            }

            sent_email: resend.Email = resend.Emails.send(params)
            logger.debug(f"Password reset email sent: {sent_email.get('id')}")

            session.commit()
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            session.rollback()
    else:
        logger.debug("No account found with the provided email.")


def generate_email_update_url(account_id: int, token: str, new_email: str) -> str:
    """
    Generates the email update confirmation URL with proper query parameters.
    """
    base_url = os.getenv('BASE_URL')
    return f"{base_url}/account/confirm_email_update?account_id={account_id}&token={token}&new_email={new_email}"


def send_email_update_confirmation(
    current_email: str,
    new_email: str,
    account_id: int,
    session: Session
) -> None:
    # Check for an existing unexpired token
    existing_token = session.exec(
        select(EmailUpdateToken)
        .where(
            EmailUpdateToken.account_id == account_id,
            EmailUpdateToken.expires_at > datetime.now(UTC),
            EmailUpdateToken.used == False
        )
    ).first()

    if existing_token:
        logger.debug("An unexpired email update token already exists for this account.")
        return

    # Generate a new token
    token = EmailUpdateToken(account_id=account_id)
    session.add(token)

    try:
        confirmation_url = generate_email_update_url(
            account_id, token.token, new_email)

        # Render the email template
        template = templates.get_template("emails/update_email_email.html")
        html_content = template.render({
            "confirmation_url": confirmation_url,
            "current_email": current_email,
            "new_email": new_email
        })

        params: resend.Emails.SendParams = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [current_email],
            "subject": "Confirm Email Update",
            "html": html_content,
        }

        sent_email: resend.Email = resend.Emails.send(params)
        logger.debug(f"Email update confirmation sent: {sent_email.get('id')}")

        session.commit()
    except Exception as e:
        logger.error(f"Failed to send email update confirmation: {e}")
        session.rollback()
