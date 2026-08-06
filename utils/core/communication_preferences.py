from typing import NamedTuple

from utils.core.models import User


class CommunicationPreferences(NamedTuple):
    comm_opt_in: bool
    comm_updates: bool
    comm_marketing: bool


def parse_communication_preferences(
    comm_opt_in: str | None = None,
    comm_updates: str | None = None,
    comm_marketing: str | None = None,
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
