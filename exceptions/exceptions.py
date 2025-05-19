from utils.core.models import User


class NeedsNewTokens(Exception):
    def __init__(self, user: User, access_token: str, refresh_token: str):
        self.user = user
        self.access_token = access_token
        self.refresh_token = refresh_token


# Define custom exception for email sending failure
class EmailSendFailedError(Exception):
    """Custom exception for email sending failures."""
    pass