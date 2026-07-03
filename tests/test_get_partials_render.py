"""Runtime smoke tests: HTMX partial GET routes must render without template errors."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from main import app
from tests.conftest import htmx_headers
from tests.frontend.helpers import assert_partial_rendered


@dataclass(frozen=True)
class PartialGetCase:
    id: str
    client_fixture: str
    path: str
    marker: str | None = None


def _url(name: str, **path_params) -> str:
    return str(app.url_path_for(name, **path_params))


PARTIAL_GET_CASES = [
    PartialGetCase(
        "profile_edit_form",
        "auth_client",
        _url("edit_profile_form"),
        marker="profile-form-actions",
    ),
    PartialGetCase(
        "profile_display",
        "auth_client",
        _url("profile_display"),
        marker="profile-card",
    ),
]


@pytest.mark.usefixtures("env_vars")
class TestHtmxPartialGetRender:
    @pytest.mark.parametrize("case", PARTIAL_GET_CASES, ids=lambda c: c.id)
    def test_partial_get_renders(
        self, case: PartialGetCase, request: pytest.FixtureRequest
    ):
        client = request.getfixturevalue(case.client_fixture)
        response = client.get(case.path, headers=htmx_headers())
        assert_partial_rendered(response)
        if case.marker:
            assert case.marker in response.text

    def test_profile_edit_form_non_htmx_redirects_to_profile(self, auth_client):
        response = auth_client.get(_url("edit_profile_form"))
        assert response.status_code == 303
        assert response.headers["location"] == _url("read_profile")

    def test_profile_display_non_htmx_redirects_to_profile(self, auth_client):
        response = auth_client.get(_url("profile_display"))
        assert response.status_code == 303
        assert response.headers["location"] == _url("read_profile")

    def test_avatar_returns_image_when_present(self, auth_client, test_user, session):
        from utils.core.models import UserAvatar

        assert test_user.id is not None
        session.add(
            UserAvatar(
                user_id=test_user.id,
                avatar_data=b"\x89PNG\r\n\x1a\n",
                avatar_content_type="image/png",
            )
        )
        session.commit()

        response = auth_client.get(_url("get_avatar"))
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/")
