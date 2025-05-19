from fastapi import HTTPException, status
from utils.core.enums import ValidPermissions

class EmailAlreadyRegisteredError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=409,
            detail="This email is already registered"
        )


class CredentialsError(HTTPException):
    def __init__(self, message: str = "Invalid credentials"):
        super().__init__(
            status_code=401,
            detail=message
        )


class AuthenticationError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )


class PasswordValidationError(HTTPException):
    def __init__(self, field: str, message: str):
        super().__init__(
            status_code=422,
            detail={
                "field": field,
                "message": message
            }
        )


class InsufficientPermissionsError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=403,
            detail="You don't have permission to perform this action"
        )


class OrganizationSetupError(HTTPException):
    def __init__(self, message: str = "Organization setup failed"):
        super().__init__(
            status_code=500,
            detail=message
        )


class OrganizationNameTakenError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Organization name already taken"
        )


class OrganizationNotFoundError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail="Organization not found"
        )


class UserNotFoundError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=404,
            detail="User not found"
        )


class UserAlreadyMemberError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="User is already a member of this organization"
        )


class InvalidPermissionError(HTTPException):
    """Raised when a user attempts to assign an invalid permission to a role"""

    def __init__(self, permission: ValidPermissions):
        super().__init__(
            status_code=400,
            detail=f"Invalid permission: {permission}"
        )


class RoleAlreadyExistsError(HTTPException):
    """Raised when attempting to create a role with a name that already exists"""

    def __init__(self):
        super().__init__(status_code=400, detail="Role already exists")


class RoleNotFoundError(HTTPException):
    """Raised when a requested role does not exist"""

    def __init__(self):
        super().__init__(status_code=404, detail="Role not found")


class RoleHasUsersError(HTTPException):
    """Raised when a requested role to be deleted has users"""

    def __init__(self):
        super().__init__(
            status_code=400,
            detail="Role cannot be deleted until users with that role are reassigned"
        )


class CannotModifyDefaultRoleError(HTTPException):
    """Raised when attempting to modify or delete a default system role."""
    def __init__(self, action: str = "modify"):
        super().__init__(
            status_code=403,
            detail=f"Default system roles cannot be {action}d."
        )


class DataIntegrityError(HTTPException):
    def __init__(
            self,
            resource: str = "Database resource"
    ):
        super().__init__(
            status_code=500,
            detail=(
                f"{resource} is in a broken state; please contact a system administrator"
            )
        )


class InvalidImageError(HTTPException):
    """Raised when an invalid image is uploaded"""

    def __init__(self, message: str = "Invalid image file"):
        super().__init__(status_code=400, detail=message)


# --- Invitation-specific Errors ---

class UserIsAlreadyMemberError(HTTPException):
    """Raised when trying to invite a user who is already a member of the organization."""
    def __init__(self):
        super().__init__(
            status_code=409,
            detail="This user is already a member of the organization."
        )


class ActiveInvitationExistsError(HTTPException):
    """Raised when trying to invite a user for whom an active invitation already exists."""
    def __init__(self):
        super().__init__(
            status_code=409,
            detail="An active invitation already exists for this email address in this organization."
        )


class InvalidRoleForOrganizationError(HTTPException):
    """Raised when a role provided does not belong to the target organization.
    Note: If the role ID simply doesn't exist, a standard 404 RoleNotFoundError should be raised.
    """
    def __init__(self):
        super().__init__(
            status_code=400,
            detail="The selected role does not belong to this organization."
        )


class InvitationEmailSendError(HTTPException):
    """Raised when the invitation email fails to send."""
    def __init__(self):
        super().__init__(
            status_code=500, # Internal Server Error seems appropriate
            detail="Failed to send invitation email. Please try again later or contact support."
        )


class InvalidInvitationTokenError(HTTPException):
    """Raised when an invitation token is invalid, expired, or not found."""
    def __init__(self):
        super().__init__(
            status_code=404,
            detail="Invitation not found or expired"
        )


class InvitationEmailMismatchError(HTTPException):
    """Raised when a user attempts to accept an invitation sent to a different email address."""
    def __init__(self):
        super().__init__(
            status_code=403,
            detail="This invitation was sent to a different email address"
        )


class InvitationProcessingError(HTTPException):
    """Raised when an error occurs during the processing of a valid invitation."""
    def __init__(self, detail: str = "Failed to process invitation. Please try again later."):
        super().__init__(
            status_code=500, # Internal Server Error
            detail=detail
        )