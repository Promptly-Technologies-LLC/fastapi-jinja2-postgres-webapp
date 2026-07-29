"""Tests for website form validation helpers."""

from utils.website.forms import BookDemoSubmission, CallMeSubmission


def test_book_demo_submission_accepts_valid_payload():
    submission, errors = BookDemoSubmission.from_form(
        work_email="owner@example.com",
        first_name="Jordan",
        last_name="Diaz",
        company="Summit Air",
        trade="HVAC",
        phone="(518) 555-0142",
        technicians="2-5",
        phone_answerer="owner",
    )
    assert errors == {}
    assert submission is not None
    assert submission.company == "Summit Air"


def test_call_me_submission_rejects_invalid_phone():
    submission, errors = CallMeSubmission.from_form(
        name="Jordan Diaz",
        business="Summit Air",
        email="jordan@summitair.com",
        phone="nope",
        industry="HVAC",
    )
    assert submission is None
    assert "phone" in errors


def test_call_me_submission_prefixes_us_phone():
    submission, errors = CallMeSubmission.from_form(
        name="Jordan Diaz",
        business="Summit Air",
        email="jordan@summitair.com",
        phone="(518) 555-0142",
        industry="HVAC",
    )
    assert errors == {}
    assert submission is not None
    assert submission.phone.startswith("+1")
    assert submission.industry == "HVAC"


def test_call_me_submission_saves_custom_crm_name():
    submission, errors = CallMeSubmission.from_form(
        name="Jordan Diaz",
        business="Summit Air",
        email="jordan@summitair.com",
        phone="(518) 555-0142",
        industry="HVAC Services",
        crm="other",
        crm_other="ShopWare Pro",
    )
    assert errors == {}
    assert submission is not None
    assert submission.crm == "ShopWare Pro"


def test_call_me_submission_requires_custom_crm_name():
    submission, errors = CallMeSubmission.from_form(
        name="Jordan Diaz",
        business="Summit Air",
        email="jordan@summitair.com",
        phone="(518) 555-0142",
        industry="HVAC Services",
        crm="other",
        crm_other="",
    )
    assert submission is None
    assert "crm_other" in errors
