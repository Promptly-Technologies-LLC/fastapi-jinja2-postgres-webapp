import os
from logging import getLogger, DEBUG
import resend
from dotenv import load_dotenv
from sqlmodel import Session
from jinja2.environment import Template
from fastapi.templating import Jinja2Templates

from utils.core.models import utc_now, Invitation, Organization, User
from exceptions.exceptions import EmailSendFailedError
from exceptions.http_exceptions import DataIntegrityError

# Load environment variables
load_dotenv(override=True)
resend.api_key = os.environ.get("RESEND_API_KEY")
BASE_URL = os.getenv("BASE_URL", "")

# Setup logging
logger = getLogger("uvicorn.error")
logger.setLevel(DEBUG)

# Setup templates
templates = Jinja2Templates(directory="templates")


def generate_invitation_link(token: str) -> str:
    """
    Generates the full invitation acceptance URL.

    Args:
        token: The unique invitation token.

    Returns:
        The complete URL for accepting the invitation.
    """
    return f"{BASE_URL}/invitations/accept?token={token}"


def send_invitation_email(invitation: Invitation, session: Session) -> None:
    """
    Sends an organization invitation email using Resend.

    Args:
        invitation: The Invitation object (ensure relationships like organization are loaded).
        session: The database session (used here primarily for potential future needs or consistency,
                 though direct DB access might be minimal if invitation object is pre-loaded).
    """
    if not resend.api_key:
        logger.error("Resend API key is not configured. Cannot send invitation email.")
        raise EmailSendFailedError("Resend API key is not configured.")

    try:
        # Ensure the organization relationship is loaded or fetch it
        org_name = "the organization" # Default name
        if invitation.organization:
            org_name = invitation.organization.name
        elif invitation.organization_id:
             # Attempt to fetch if not loaded - requires Organization model import
            org = session.get(Organization, invitation.organization_id)
            if org:
                org_name = org.name
            else:
                logger.error(
                    f"Could not find organization with ID {invitation.organization_id} "
                    f"for invitation {invitation.id}"
                )
                raise DataIntegrityError(resource="Organization")


        invitation_link = generate_invitation_link(invitation.token)

        # Render the email template
        template: Template = templates.get_template("emails/organization_invite.html")
        html_content: str = template.render(
            {
                "organization_name": org_name,
                "acceptance_link": invitation_link,
                # Add other context variables needed by the template if any
            }
        )

        params: resend.Emails.SendParams = {
            "from": os.getenv("EMAIL_FROM", ""),
            "to": [invitation.invitee_email],
            "subject": f"You're invited to join {org_name}",
            "html": html_content,
        }

        sent_email: resend.Email = resend.Emails.send(params)
        logger.info(
            f"Organization invitation email sent to {invitation.invitee_email}: {sent_email.get('id')}"
        )

    except Exception as e:
        logger.error(
            f"Failed to send organization invitation email to {invitation.invitee_email}: {e}",
            exc_info=True
        )
        raise EmailSendFailedError() from e


def process_invitation(invitation: Invitation, accepted_by_user: User, session: Session) -> None:
    """
    Processes an accepted invitation.

    - Adds the user to the organization's role.
    - Marks the invitation as used.
    - Updates invitation timestamps and accepted user.

    Args:
        invitation: The Invitation object to process (should have relationships loaded or be refreshed).
        accepted_by_user: The User who accepted the invitation.
        session: The database session.
    """
    # Refresh to ensure relationships are loaded, especially if coming from a dependency
    session.refresh(invitation, attribute_names=["organization", "role"])

    # Add the user to the role associated with the invitation
    if invitation.role:
        accepted_by_user.roles.append(invitation.role)
        # Note: SQLAlchemy handles the association table updates automatically here.
    else:
        # This should ideally not happen if validation is correct upstream, but handle defensively.
        logger.error(f"Invitation {invitation.id} is missing associated role during processing.")
        raise DataIntegrityError(resource="Invitation role")

    # Mark the invitation as used
    invitation.used = True
    invitation.accepted_at = utc_now()
    invitation.accepted_by_user_id = accepted_by_user.id

    # Add the updated invitation to the session (will be updated on commit)
    session.add(invitation)
    # IMPORTANT: The session is NOT committed here. The calling endpoint must handle the commit.
    logger.info(f"Processed invitation {invitation.id} for user {accepted_by_user.id} and role {invitation.role_id}")
