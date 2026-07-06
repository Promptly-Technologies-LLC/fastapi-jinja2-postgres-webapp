"""Direct DB helpers for browser tests (separate webapp-browser-test-db)."""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from datetime import timedelta

from dotenv import load_dotenv
from sqlmodel import Session, create_engine, select

from utils.core.auth import get_password_hash
from utils.core.db import create_default_roles, get_connection_url
from utils.core.models import (
    Account,
    Invitation,
    Organization,
    Role,
    User,
    utc_naive_now,
)


def browser_db_env() -> dict[str, str]:
    load_dotenv()
    env = os.environ.copy()
    env["DB_NAME"] = "webapp-browser-test-db"
    env["SECRET_KEY"] = "testsecretkey-that-is-at-least-32-bytes-long"
    env["HOST_NAME"] = "Test Organization"
    env["RESEND_API_KEY"] = "test"
    env["EMAIL_FROM"] = "test@example.com"
    return env


@contextmanager
def browser_db_session():
    env = browser_db_env()
    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        engine = create_engine(get_connection_url())
        with Session(engine) as session:
            yield session
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def get_host_organization(session: Session) -> Organization:
    host_name = os.getenv("HOST_NAME", "Test Organization")
    org = session.exec(
        select(Organization).where(Organization.name == host_name)
    ).first()
    if org is None:
        org = Organization(name=host_name)
        session.add(org)
        session.flush()
        assert org.id is not None
        create_default_roles(session, org.id, check_first=False)
        session.commit()
        session.refresh(org)
    return org


def add_member_to_host_org(
    session: Session,
    *,
    email: str,
    password: str,
    name: str = "Browser Member",
) -> tuple[User, Organization]:
    org = get_host_organization(session)
    assert org.id is not None
    member_role = session.exec(
        select(Role).where(Role.organization_id == org.id, Role.name == "Member")
    ).first()
    if member_role is None:
        raise RuntimeError("Member role not found for host organization")

    account = Account(email=email, hashed_password=get_password_hash(password))
    session.add(account)
    session.flush()
    user = User(name=name, account_id=account.id)
    user.roles.append(member_role)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user, org


def seed_invitation(
    session: Session,
    *,
    organization_id: int,
    role_id: int,
    invitee_email: str,
    token: str | None = None,
    expired: bool = False,
) -> Invitation:
    invitation = Invitation(
        organization_id=organization_id,
        role_id=role_id,
        invitee_email=invitee_email,
        token=token or str(uuid.uuid4()),
        expires_at=(
            utc_naive_now() - timedelta(days=1)
            if expired
            else utc_naive_now() + timedelta(days=7)
        ),
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation


def get_member_role_id(session: Session, organization_id: int) -> int:
    role = session.exec(
        select(Role).where(
            Role.organization_id == organization_id,
            Role.name == "Member",
        )
    ).first()
    if role is None or role.id is None:
        raise RuntimeError("Member role not found")
    return role.id


def add_member_to_organization(
    session: Session,
    organization_id: int,
    *,
    email: str,
    password: str,
    name: str = "Browser Member",
) -> User:
    member_role_id = get_member_role_id(session, organization_id)
    member_role = session.get(Role, member_role_id)
    if member_role is None:
        raise RuntimeError("Member role not found")

    account = Account(email=email, hashed_password=get_password_hash(password))
    session.add(account)
    session.flush()
    user = User(name=name, account_id=account.id)
    user.roles.append(member_role)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def browser_csrf_db_env() -> dict[str, str]:
    env = browser_db_env()
    env["DB_NAME"] = "webapp-browser-csrf-test-db"
    env["BASE_URL"] = "http://127.0.0.1:8114"
    env["CSRF_ENABLED"] = "1"
    return env


@contextmanager
def browser_csrf_db_session():
    env = browser_csrf_db_env()
    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        engine = create_engine(get_connection_url())
        with Session(engine) as session:
            yield session
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
