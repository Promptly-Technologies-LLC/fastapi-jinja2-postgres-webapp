from typing import NamedTuple, Optional

from utils.core.models import User


class CommunicationPreferences(NamedTuple):
    comm_opt_in: bool
    comm_updates: bool
    comm_marketing: bool


def parse_communication_preferences(
    comm_opt_in: Optional[str] = None,
    comm_updates: Optional[str] = None,
    comm_marketing: Optional[str] = None,
) -> CommunicationPreferences:
    """Parse HTML checkbox form values into communication preference booleans."""
    if comm_opt_in != "on":
        return CommunicationPreferences(False, False, False)
    return CommunicationPreferences(
        True,
        comm_updates == "on",
        comm_marketing == "on",
    )


def apply_communication_preferences(
    user: User, prefs: CommunicationPreferences
) -> None:
    user.comm_opt_in = prefs.comm_opt_in
    user.comm_updates = prefs.comm_updates
    user.comm_marketing = prefs.comm_marketing
