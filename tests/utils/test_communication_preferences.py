from utils.core.communication_preferences import parse_communication_preferences


def test_parse_communication_preferences_all_off_by_default():
    prefs = parse_communication_preferences()
    assert prefs == (False, False, False)


def test_parse_communication_preferences_master_off_ignores_subs():
    prefs = parse_communication_preferences(
        comm_opt_in=None,
        comm_updates="on",
        comm_marketing="on",
    )
    assert prefs == (False, False, False)


def test_parse_communication_preferences_master_on_with_subs():
    prefs = parse_communication_preferences(
        comm_opt_in="on",
        comm_updates="on",
        comm_marketing="on",
    )
    assert prefs == (True, True, True)


def test_parse_communication_preferences_master_on_updates_only():
    prefs = parse_communication_preferences(
        comm_opt_in="on",
        comm_updates="on",
        comm_marketing=None,
    )
    assert prefs == (True, True, False)
